use crate::BatchResult;
use crate::BenchArgs;
use crate::Benchmark;
use crate::BenchmarkResult;
use crate::Benchmarks;
use crate::Bin;
use crate::LinkerKind;
use crate::Result;
use crate::Run;
use crate::config::Config;
use anyhow::Context as _;
use anyhow::bail;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::io::Read as _;
use std::process::Command;
use std::process::Stdio;
use std::time::Instant;
use wait4::Wait4 as _;

pub(crate) fn run_bench(args: &BenchArgs, config: &Config) -> Result {
    if !args.allow_non_tmpfs {
        check_tmpfs(args)?;
    }

    let bins = args
        .binaries
        .iter()
        .enumerate()
        .map(|(i, bin_path)| Bin::new(bin_path, i as u32))
        .collect::<Result<Vec<Bin>>>()?;

    let benchmarks = find_benchmarks(args, config)?;

    let benchmarks = filter_benchmarks_by_wild_version(benchmarks, &bins);

    println!("Binaries:");
    for bin in &bins {
        println!("  {bin}");
    }

    println!("Benchmarks:");
    for bench in &benchmarks {
        println!("  {bench}");
    }

    if !args.no_verify {
        verify(&bins, &benchmarks, args)?;
    }

    let results = run(&bins, &benchmarks, args)?;

    let output_path = crate::default_result_path(config, &args.output);

    std::fs::write(&output_path, postcard::to_stdvec(&results)?)
        .with_context(|| format!("Failed to write `{}`", output_path.display()))?;

    Ok(())
}

fn check_tmpfs(args: &BenchArgs) -> Result {
    let tmpfile = std::path::absolute(&args.tmp)?;
    let tmpdir = tmpfile.parent().unwrap();

    let output = Command::new("stat")
        .arg("-f")
        .arg("-c")
        .arg("%T")
        .arg(tmpdir)
        .output()
        .context("Failed to run `stat`")?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if !stdout.contains("tmpfs") {
        bail!(
            "{} uses filesystem {}, but we need tmpfs for reliable benchmarking. \
            Set --tmp to something else or pass --allow-non-tmpfs to ignore",
            tmpdir.display(),
            stdout.trim(),
        );
    }
    Ok(())
}

fn run(bins: &[Bin], benchmarks: &[Benchmark], args: &BenchArgs) -> Result<Benchmarks> {
    let mut out = Vec::new();
    let start = Instant::now();

    for (bench_index, bench) in benchmarks.iter().enumerate() {
        let bench_start = Instant::now();
        let message = format!(
            "Benchmark {} of {}: {bench}",
            bench_index + 1,
            benchmarks.len()
        );

        let progress_bar = indicatif::ProgressBar::new(
            (args.num_batches * args.batch_size * bins.len() as u32) as u64,
        )
        .with_style(indicatif::ProgressStyle::with_template(
            "{msg} {spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}]",
        )?)
        .with_message(message.clone());

        // Ensure the benchmark inputs are in cache.
        let warmup_bin = bins.last().context("Need at least one binary")?;
        run_once(warmup_bin, bench, args, &[])?;

        let mut bench_results = Vec::new();
        for batch_num in 0..args.num_batches {
            for bin in bins {
                let mut bin_results = Vec::new();
                for _ in 0..args.batch_size {
                    let extra_flags = if !args.no_mem && batch_num == 0 {
                        ["--no-fork"].as_slice()
                    } else {
                        &[]
                    };

                    if let Some(run) = run_once(bin, bench, args, extra_flags)? {
                        bin_results.push(run);
                    }
                    progress_bar.inc(1);
                }
                bench_results.push(BatchResult {
                    bin: bin.clone(),
                    runs: bin_results,
                })
            }
        }
        bench_results.sort_by_key(|b| b.bin.index);
        let r = BenchmarkResult {
            config: bench.clone(),
            batches: bench_results,
        };
        out.push(r);
        progress_bar.finish_and_clear();
        println!("{message}: done in {} s", bench_start.elapsed().as_secs());
    }

    let elapsed = start.elapsed();
    println!(
        "All done in {}h {}m {}s",
        elapsed.as_secs() / 3600,
        (elapsed.as_secs() / 60) % 60,
        elapsed.as_secs() % 60
    );

    Ok(Benchmarks { benchmarks: out })
}

/// Runs each benchmark once with each linker.
fn verify(bins: &[Bin], benchmarks: &[Benchmark], args: &BenchArgs) -> Result {
    let mut success = true;
    for bench in benchmarks {
        println!("Verifying: {bench}");
        for bin in bins {
            if let Err(error) = run_once(bin, bench, args, &[]) {
                eprintln!("{error}");
                success = false;
            }
        }
    }

    if !success {
        bail!("One or more benchmark/linker combinations failed");
    }

    Ok(())
}

fn run_once(
    bin: &Bin,
    bench: &Benchmark,
    args: &BenchArgs,
    extra_flags: &[&str],
) -> Result<Option<Run>> {
    if !bench.supports_bin(bin) {
        return Ok(None);
    }

    let mut command = Command::new(&bench.path);
    command.env("OUT", args.tmp.as_os_str()).arg(&bin.path);
    for arg in extra_flags {
        if bin.identifier.kind.supports_arg(arg) {
            command.arg(arg);
        }
    }

    let (mut pipe_read, pipe_write) = std::io::pipe()?;
    command
        .stderr(pipe_write.try_clone()?)
        .stdout(pipe_write)
        .stdin(Stdio::null());

    let start = Instant::now();

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to run {command:?}"))?;

    // Ensure we're not holding any copies of the write-end of the pipe in the parent process,
    // otherwise the read below won't terminate.
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());

    let mut text_out = String::new();
    pipe_read.read_to_string(&mut text_out)?;

    let pid = child.id();

    let res_use = child.wait4()?;

    let elapsed = start.elapsed();

    if !res_use.status.success() {
        bail!("Error returned from {command:?}\n{text_out}",)
    }

    // Make sure that the linker runs without warning. Specifically what we care about is that the
    // linker is being invoked without any flags that it doesn't properly support, since that might
    // be unfair to other linkers that do support that option.
    if text_out.contains("WARN") {
        bail!("Command produced warnings: {command:?}\n{text_out}");
    }

    // However long we took to run, sleep for half of that. If the linker forked on startup, then
    // this gives the subprocess a chance to shutdown in the background before we run the next
    // command.
    std::thread::sleep(elapsed / 2);

    Ok(Some(Run {
        pid,
        extra_flags: extra_flags.iter().map(|f| (*f).to_owned()).collect(),
        elapsed,
        max_rss: res_use.rusage.maxrss,
        stime: res_use.rusage.stime,
        utime: res_use.rusage.utime,
    }))
}

fn find_benchmarks(args: &BenchArgs, config: &Config) -> Result<Vec<Benchmark>> {
    let dir = args.saves.as_path();

    let mut benchmarks = Vec::new();

    let mut available: BTreeSet<String> = std::fs::read_dir(dir)
        .with_context(|| format!("Save dir doesn't exist `{}`", dir.display()))?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().map(|s| s.to_owned()))
        .collect();

    for (name, config) in &config.benches {
        available.remove(name);
        if !config.skip {
            benchmarks.push(Benchmark::new(dir.join(name), config.clone())?);
        }
    }

    if !available.is_empty() {
        let mut config_snippet = String::new();
        for a in available {
            config_snippet += &format!("[bench.{a}]\n\n");
        }
        bail!("Config doesn't list some benchmarks. Please add:\n{config_snippet}");
    }

    if !args.benches.is_empty() {
        let keep: HashSet<&str> = args.benches.iter().map(|n| n.as_str()).collect();
        benchmarks.retain(|b| keep.contains(b.name.as_str()));
    }

    Ok(benchmarks)
}

/// Filter benchmarks to just those that have at least one supported Wild version.
fn filter_benchmarks_by_wild_version(benchmarks: Vec<Benchmark>, bins: &[Bin]) -> Vec<Benchmark> {
    let Some(maximum_wild_version) = bins
        .iter()
        .filter(|&bin| bin.identifier.kind == LinkerKind::Wild)
        .map(|bin| &bin.identifier.effective_version)
        .max()
    else {
        return benchmarks;
    };

    benchmarks
        .into_iter()
        .filter(|bench| {
            if !bench.supports_wild_version(maximum_wild_version) {
                println!("Skipping benchmark {bench} due to minimum version requirement");
                false
            } else {
                true
            }
        })
        .collect()
}
