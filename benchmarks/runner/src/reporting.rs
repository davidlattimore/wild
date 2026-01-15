use crate::BatchResult;
use crate::BenchmarkResult;
use crate::Benchmarks;
use crate::LinkerKind;
use crate::ReportArgs;
use crate::Result;
use crate::config::BenchConfig;
use crate::config::Config;
use anyhow::Context as _;
use std::collections::HashSet;
use std::fmt::Display;
use std::fmt::Write as _;
use std::path::Path;
use std::path::PathBuf;

const IMAGES_SUBDIR_NAME: &str = "images";

pub(crate) fn run_report(args: &ReportArgs, config: &Config) -> Result {
    let input_path = crate::default_result_path(config, &args.input);
    let report_dir = &args.dir;
    let target_subdir = report_dir.join(IMAGES_SUBDIR_NAME).join(&config.name);
    std::fs::create_dir_all(&target_subdir)
        .with_context(|| format!("Failed to create directory `{}`", target_subdir.display()))?;
    let bytes = std::fs::read(&input_path)
        .with_context(|| format!("Failed to read `{}`", input_path.display()))?;
    let results: Benchmarks = postcard::from_bytes(&bytes)
        .with_context(|| format!("Failed to parse `{}`", input_path.display()))?;

    let markdown_path = report_dir.join(format!("{}.md", config.name));

    let mut markdown = std::fs::read_to_string(&markdown_path).unwrap_or_default();

    let mut existing_images: HashSet<PathBuf> = std::fs::read_dir(target_subdir)
        .ok()
        .map(|dir| {
            dir.filter_map(|ent| ent.ok().map(|ent| ent.path()))
                .collect()
        })
        .unwrap_or_default();

    const UNGROUPED_HEADER: &str = "## UNGROUPED\n";

    for mode in [ReportMode::Time, ReportMode::Memory] {
        for benchmark in &results.benchmarks {
            let Some(bench_config) = config.benches.get(&benchmark.config.name) else {
                continue;
            };
            if bench_config.skip {
                continue;
            }
            let mut benchmark = mode.filter(benchmark, bench_config);
            merge_batches(&mut benchmark);
            if benchmark.batches.is_empty() {
                continue;
            }
            let svg_filename = produce_chart(report_dir, &benchmark, mode, config)?;
            existing_images.remove(&report_dir.join(&svg_filename));

            // Check to see if the markdown already has a link to this file. If it doesn't, add one.
            // This allows us to edit the markdown, regenerate the report and add new benchmarks
            // without losing previous edits.
            if !markdown.contains(&svg_filename) {
                if !markdown.contains(UNGROUPED_HEADER) {
                    markdown.push_str(UNGROUPED_HEADER);
                }
                markdown.push_str(&format!(
                    "### {} - {mode}\n![{alt}]({svg_filename})\n\n",
                    benchmark.config.name,
                    alt = alt_text(mode, &benchmark)
                ));
            }

            if args.print_stats {
                println!(
                    "{}",
                    BenchmarkDisplay {
                        benchmark: &benchmark,
                        mode
                    }
                );
            }
        }
    }

    for path in existing_images {
        println!("Deleting stale image {}", path.display());
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to delete `{}`", path.display()))?;
    }

    std::fs::write(&markdown_path, &markdown)
        .with_context(|| format!("Failed to write `{}`", markdown_path.display()))?;

    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReportMode {
    Time,
    Memory,
}

impl ReportMode {
    fn filter(self, benchmark: &BenchmarkResult, config: &BenchConfig) -> BenchmarkResult {
        let mut benchmark = benchmark.clone();

        benchmark
            .batches
            .iter_mut()
            .for_each(|batch| batch.runs.retain(|run| self.should_keep_run(run)));

        benchmark.batches.retain(|batch| {
            !batch.runs.is_empty() && !config.skip_linkers.contains(&batch.bin.identifier.kind)
        });

        benchmark
    }

    fn should_keep_run(&self, run: &crate::Run) -> bool {
        run.extra_flags.iter().any(|f| f == "--no-fork") == (self == &ReportMode::Memory)
    }

    fn unit_name(self) -> &'static str {
        match self {
            ReportMode::Time => "ms",
            ReportMode::Memory => "MiB",
        }
    }

    fn unit_multiplier(self) -> f64 {
        match self {
            ReportMode::Time => 1000_f64,
            ReportMode::Memory => 1_f64 / (1024 * 1024) as f64,
        }
    }

    /// Gets the mean value converted in to the unit that `unit_name` returns.
    fn get_value(self, b: &BatchResult) -> f64 {
        mean(b, self) * self.unit_multiplier()
    }

    fn raw_value(self, r: &crate::Run) -> f64 {
        match self {
            ReportMode::Time => r.elapsed.as_secs_f64(),
            ReportMode::Memory => r.max_rss as f64,
        }
    }
}

fn alt_text(mode: ReportMode, benchmark: &BenchmarkResult) -> String {
    match mode {
        ReportMode::Time => format!("Time to link {}", benchmark.config.name),
        ReportMode::Memory => format!("Memory consumption while linking {}", benchmark.config.name),
    }
}

fn mean(batch_result: &BatchResult, mode: ReportMode) -> f64 {
    let total: f64 = batch_result.runs.iter().map(|r| mode.raw_value(r)).sum();
    total / batch_result.runs.len() as f64
}

fn std_def(batch_result: &BatchResult, mode: ReportMode) -> f64 {
    let mean = mean(batch_result, mode);
    let sum: f64 = batch_result
        .runs
        .iter()
        .map(|r| {
            let diff = mode.raw_value(r) - mean;
            diff * diff
        })
        .sum();
    (sum / batch_result.runs.len() as f64).sqrt()
}

fn std_err(batch_result: &BatchResult, mode: ReportMode) -> f64 {
    std_def(batch_result, mode) / (batch_result.runs.len() as f64).sqrt()
}

/// Returns the 99% confidence interval.
fn confidence_interval(batch_result: &BatchResult, mode: ReportMode) -> f64 {
    std_err(batch_result, mode) * 2.5758
}

struct BenchmarkDisplay<'a> {
    benchmark: &'a BenchmarkResult,
    mode: ReportMode,
}

impl Display for BenchmarkDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} {}:", self.benchmark.config.name, self.mode)?;
        for r in &self.benchmark.batches {
            writeln!(
                f,
                "  {bin}: {val:.2} ± {conf:.2} {units}",
                bin = r.bin,
                val = mean(r, self.mode) * self.mode.unit_multiplier(),
                conf = confidence_interval(r, self.mode) * self.mode.unit_multiplier(),
                units = self.mode.unit_name(),
            )?;
        }
        Ok(())
    }
}

fn produce_chart(
    report_dir: &Path,
    benchmark: &BenchmarkResult,
    mode: ReportMode,
    config: &Config,
) -> Result<String> {
    let svg_name = format!(
        "{}/{}/{}-{mode}.svg",
        IMAGES_SUBDIR_NAME, config.name, benchmark.config.name
    );
    let svg_path = report_dir.join(&svg_name);

    let max_value = max_positive_f64(
        benchmark
            .batches
            .iter()
            .map(|b| (mean(b, mode) + confidence_interval(b, mode)) * mode.unit_multiplier()),
    );

    let step = compute_step(max_value as u32);

    let chart_max = (max_value.ceil() as u32).next_multiple_of(step);

    let chart_width = 1000;
    let chart_height = 600;
    let bg = "#000000";
    let fg = "#FFFFFF";
    let title = format!("{} - {} - {mode}", config.name, benchmark.config.name);
    let unit_label_y = chart_height / 2;
    let unit = mode.unit_name();

    // I tried using plotters to render the charts. It worked, but there were a few things that it
    // seemed like I couldn't control. Also, the files were larger than they needed to be. SVG is
    // simple enough that we just render it ourselves. That gives us total control.
    let mut svg = String::new();

    writeln!(
        &mut svg,
        r#"<svg width="{chart_width}" height="{chart_height}" viewBox="0 0 {chart_width} {chart_height}" xmlns="http://www.w3.org/2000/svg">
<rect x="0" y="0" width="{chart_width}" height="{chart_height}" fill="{bg}"/>
<text x="500" y="10" dy="0.8em" text-anchor="middle" font-family="sans-serif" font-size="40" fill="{fg}">
{title}</text>
<text x="5" y="{unit_label_y}" dy="0.76em" text-anchor="middle" font-family="sans-serif" 
font-size="16" fill="{fg}" transform="rotate(270, 5, 288)">{unit}</text>"#
    )?;

    // The area of our data.
    let left = 100;
    let right = chart_width - 50;
    let top = 80;
    let bottom = chart_height - 140;

    let unit_label_x = left - 10;

    let value_to_y = |v: f64| bottom - (v / chart_max as f64 * (bottom - top) as f64) as u32;

    for val in (0..=chart_max).step_by(step as usize) {
        // Draw horizontal lines.
        let val_str = format_number(val);
        let y = value_to_y(val as f64);
        writeln!(
            &mut svg,
            r#"<line x1="{left}" y1="{y}" x2="{right}" y2="{y}" stroke="{fg}" />"#
        )?;

        // Draw numbers for each line.
        writeln!(
            &mut svg,
            r#"<text x="{unit_label_x}" y="{y}" dy="0.5ex" text-anchor="end" fill="{fg}">{val_str}</text>"#
        )?;
    }

    let bar_width = (right - left) / benchmark.batches.len() as u32;
    let bar_margin = bar_width / 10;

    for (i, b) in benchmark.batches.iter().enumerate() {
        // Draw the main bar.
        let value = mode.get_value(b);
        let y = value_to_y(value);
        let x = bar_width * i as u32 + left + bar_margin;
        let w = bar_width - bar_margin * 2;
        let h = bottom - y;
        let colour = colour_for(b.bin.identifier.kind);
        writeln!(
            &mut svg,
            r#"<rect fill="{colour}" opacity="0.8" x="{x}" y="{y}" width="{w}" height="{h}" />"#
        )?;

        // Draw a confidence interval bar.
        let interval = confidence_interval(b, mode) * mode.unit_multiplier();
        let y1 = value_to_y(value + interval);
        let y2 = value_to_y(value - interval);
        let x = x + w / 2;
        writeln!(
            &mut svg,
            r#"<line stroke="{fg}" x1="{x}" y1="{y1}" x2="{x}" y2="{y2}" />"#
        )?;

        // Draw the name of the linker.
        let x = bar_width * i as u32 + left + bar_width / 2;
        let mut y = bottom + 6;
        let line_spacing = 18;
        for line in b.bin.identifier.name_parts() {
            y += line_spacing;
            writeln!(
                &mut svg,
                r#"<text x="{x}" y="{y}" fill="{fg}" text-anchor="middle">{line}</text>"#
            )?;
        }

        // Draw the percent change relative to the baseline (the last linker).
        let y = chart_height - 20;
        let baseline = benchmark
            .batches
            .last()
            .map(|b| mode.get_value(b))
            .unwrap_or(0.0);
        let extra = ((value / baseline) * 100_f64).round() as i32 - 100;
        writeln!(
            &mut svg,
            r#"<text x="{x}" y="{y}" fill="{fg}" text-anchor="middle">{extra:+.0}%</text>"#
        )?;
    }

    writeln!(&mut svg, r#"</svg>"#)?;

    std::fs::write(&svg_path, &svg)
        .with_context(|| format!("Failed to write `{}`", svg_path.display()))?;

    Ok(svg_name)
}

fn format_number(mut val: u32) -> String {
    // I'm sure there's a crate to do this, however from a security perspective, I'd prefer not to
    // depend on too many trivial crates.
    let mut out = Vec::new();
    while val >= 1000 {
        out.push(format!(" {:03}", val % 1000));
        val /= 1000;
    }
    format!("{val}{}", out.join(""))
}

/// Returns the maximum positive value, or 0 if there aren't any positive values. Ignores NaNs.
fn max_positive_f64(values: impl Iterator<Item = f64>) -> f64 {
    let mut max = 0_f64;
    for value in values {
        if value > max {
            max = value;
        }
    }
    max
}

fn compute_step(max: u32) -> u32 {
    let mut m = 1;
    while m < 100_000_000 {
        for b in [1, 2, 5] {
            let step = m * b;
            if step * 10 > max {
                return step;
            }
        }
        m *= 10;
    }
    m
}

fn colour_for(linker: LinkerKind) -> &'static str {
    match linker {
        LinkerKind::Wild => "#00FF00",
        LinkerKind::Lld => "#0000FF",
        LinkerKind::Mold => "#FF00FF",
        LinkerKind::Bfd => "#009999",
    }
}

fn merge_batches(benchmark: &mut BenchmarkResult) {
    let num_bins = benchmark
        .batches
        .iter()
        .map(|b| b.bin.index + 1)
        .max()
        .unwrap_or(0) as usize;

    let mut by_bin: Vec<Option<BatchResult>> = vec![None; num_bins];
    std::mem::take(&mut benchmark.batches)
        .into_iter()
        .for_each(|mut b| match &mut by_bin[b.bin.index as usize] {
            Some(existing) => existing.runs.append(&mut b.runs),
            n => *n = Some(b),
        });

    benchmark.batches = by_bin.into_iter().flatten().collect();
}

impl Display for ReportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportMode::Time => write!(f, "time"),
            ReportMode::Memory => write!(f, "memory"),
        }
    }
}
