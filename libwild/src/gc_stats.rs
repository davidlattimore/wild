//! Optionally writes garbage collection statistics to a text file. To use this, pass
//! `--write-gc-stats=/path/to/file.txt`
//!
//! You can also ignore selected files by passing `--gc-stats-ignore=some-string`.
//! Any files that contain `some-string` in their filename will be ignored.
//!
//! By default, only the stats per input file and the totals for all input files are shown. If you'd
//! like to also see what sections are discarded, you can run with `--verbose-gc-stats`.
//!
//! Note that only .text sections are reported, the other sections like .data, .rodata and .bss
//! are commonly garbage collected, but ignored for the purpose of this report.
//!
//! Example usage:
//!
//! ```sh
//! cargo rustc --bin rg -- -Clinker=/usr/bin/clang-15 -Clink-arg=--ld-path=wild -Clink-arg=-Wl,--write-gc-stats=/tmp/gc-stats.txt -Clink-arg=-Wl,--verbose-gc-stats
//! ```

use crate::args::Args;
use crate::error::Context as _;
use crate::error::Result;
use crate::layout::FileLayout;
use crate::layout::GroupLayout;
use crate::output_section_id;
use crate::platform::ObjectFile as _;
use crate::resolution::SectionSlot;
use hashbrown::HashMap;
use itertools::Itertools;
use std::path::PathBuf;

pub(crate) fn maybe_write_gc_stats(group_layouts: &[GroupLayout], args: &Args) -> Result {
    let Some(stats_file) = args.write_gc_stats.as_ref() else {
        return Ok(());
    };
    write_gc_stats(group_layouts, stats_file, args)
        .with_context(|| format!("Failed to write GC stats to `{}`", stats_file.display()))
}

struct InputFile<'data> {
    path: PathBuf,
    kept: u64,
    discarded: u64,
    discarded_names: Vec<&'data [u8]>,
}

fn write_gc_stats(
    group_layouts: &[GroupLayout],
    stats_file: &std::path::Path,
    args: &Args,
) -> Result {
    use std::io::Write as _;

    let mut kept = 0;
    let mut discarded = 0;
    let current_dir = std::fs::canonicalize(std::env::current_dir()?)?;
    let mut files = HashMap::new();
    for group in group_layouts {
        for file in &group.files {
            let FileLayout::Object(obj) = file else {
                continue;
            };
            let file_display_name = obj.input.file.filename.to_string_lossy();
            if args
                .gc_stats_ignore
                .iter()
                .any(|ignore| file_display_name.contains(ignore))
            {
                continue;
            }

            // Group by input filename. If the file is an archive (e.g. an rlib), then there can be
            // multiple objects within it.
            let file_record = files
                .entry(&obj.input.file.filename)
                .or_insert_with(|| InputFile {
                    path: obj.input.file.filename.clone(),
                    kept: 0,
                    discarded: 0,
                    discarded_names: Default::default(),
                });

            let mut file_kept = 0;
            let mut file_discarded = 0;
            for (slot, section) in obj.sections.iter().zip(obj.object.section_iter()) {
                match slot {
                    SectionSlot::Unloaded(unloaded) => {
                        if unloaded.part_id.output_section_id() == output_section_id::TEXT {
                            file_discarded += obj.object.section_size(section)?;
                            if args.verbose_gc_stats {
                                file_record
                                    .discarded_names
                                    .push(obj.object.section_name(section)?);
                            }
                        }
                    }
                    SectionSlot::Loaded(s) => {
                        if s.part_id.output_section_id() == output_section_id::TEXT {
                            file_kept += obj.object.section_size(section)?;
                        }
                    }
                    _ => {}
                }
            }

            file_record.kept += file_kept;
            file_record.discarded += file_discarded;

            kept += file_kept;
            discarded += file_discarded;
        }
    }

    let mut files = files.values().collect_vec();
    files.sort_by_key(|f| (f.discarded, &f.path));

    let mut out = std::io::BufWriter::new(
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(stats_file)?,
    );

    for f in &files {
        let total = f.discarded + f.kept;
        if total == 0 {
            continue;
        }
        let percent = f.discarded * 100 / total;
        writeln!(
            &mut out,
            "Discarded {}. {percent}% of {} from {}",
            Bytes(f.discarded),
            Bytes(total),
            f.path.display()
        )?;
        for section_name in &f.discarded_names {
            writeln!(&mut out, "  {}", String::from_utf8_lossy(section_name))?;
        }
    }

    let total = kept + discarded;
    let percent = discarded * 100 / total;
    writeln!(
        &mut out,
        "Discarded {}. {percent}% of executable code ({}) in {}.",
        Bytes(discarded),
        Bytes(total),
        current_dir.display()
    )?;
    Ok(())
}

struct Bytes(u64);

impl std::fmt::Display for Bytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bytesize::ByteSize(self.0))
    }
}
