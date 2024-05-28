//! Optionally writes garbage collection statistics to a text file. To use this, pass
//! `--write-gc-stats=/path/to/file.txt`
//!
//! Only input files under the current working directory will be included in the GC stats. This is
//! because the purpose of writing these stats is to see how much of the code we just compiled is
//! actually being used. We assume that the code we just compiled is somewhere in a subdirectory of
//! the current directory.
//!
//! You can also ignore selected files even if they're under the current directory by passing
//! `--gc-stats-ignore=some-string`. Any files that contain `some-string` in their filename will be
//! ignored.
//!
//! You can get rustc to pass arguments to the linker, like
//! `-Clink-arg=-Wl,--write-gc-stats=/path-to-file.txt`.

use crate::args::Args;
use crate::error::Result;
use crate::layout::FileLayout;
use crate::output_section_id;
use crate::output_section_id::TemporaryOutputSectionId;
use crate::resolution::SectionSlot;
use anyhow::Context as _;
use object::LittleEndian;
use std::collections::HashMap;
use std::path::PathBuf;

pub(crate) fn maybe_write_gc_stats(file_layouts: &[FileLayout], args: &Args) -> Result {
    let Some(stats_file) = args.write_gc_stats.as_ref() else {
        return Ok(());
    };
    write_gc_stats(file_layouts, stats_file, args)
        .with_context(|| format!("Failed to write GC stats to `{}`", stats_file.display()))
}

struct InputFile {
    path: PathBuf,
    kept: u64,
    discarded: u64,
}

fn write_gc_stats(
    file_layouts: &[FileLayout],
    stats_file: &std::path::Path,
    args: &Args,
) -> Result {
    use std::io::Write as _;

    let mut kept = 0;
    let mut discarded = 0;
    let current_dir = std::fs::canonicalize(std::env::current_dir()?)?;
    let mut files = HashMap::new();
    for file in file_layouts {
        let FileLayout::Object(obj) = file else {
            continue;
        };
        // Ignore files outside of our current working directory. Our use-case for GC stats is to
        // see how much code we compiled, but then discarded at link time. Code outside of our
        // current directory is code that we didn't just compile.
        let filename = std::fs::canonicalize(&obj.input.file.filename)?;
        if !filename.starts_with(&current_dir) {
            continue;
        }
        let file_display_name = obj.input.file.filename.to_string_lossy();
        if args
            .gc_stats_ignore
            .iter()
            .any(|ignore| file_display_name.contains(ignore))
        {
            continue;
        }
        let mut file_kept = 0;
        let mut file_discarded = 0;
        for (slot, section) in obj.sections.iter().zip(obj.object.sections.iter()) {
            match slot {
                SectionSlot::Unloaded(s) => match s.output_section_id {
                    TemporaryOutputSectionId::BuiltIn(id) => {
                        if id == output_section_id::TEXT {
                            file_discarded += section.sh_size.get(LittleEndian);
                        }
                    }
                    _ => {}
                },
                SectionSlot::Loaded(s) => {
                    if s.output_section_id == Some(output_section_id::TEXT) {
                        file_kept += section.sh_size.get(LittleEndian);
                    }
                }
                _ => {}
            }
        }

        // Group by input filename. If the file is an archive (e.g. an rlib), then there can be
        // multiple objects within it.
        let file_record = files
            .entry(&obj.input.file.filename)
            .or_insert_with(|| InputFile {
                path: obj.input.file.filename.clone(),
                kept: 0,
                discarded: 0,
            });
        file_record.kept += file_kept;
        file_record.discarded += file_discarded;

        kept += file_kept;
        discarded += file_discarded;
    }

    let mut files = files.values().collect::<Vec<_>>();
    files.sort_by_key(|f| f.discarded);

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
        let v = self.0;
        if v < 10 * 1024 {
            return write!(f, "{v} B");
        }
        if v < 10 * 1024 * 1024 {
            return write!(f, "{} KiB", v / 1024);
        }
        write!(f, "{} MiB", v / 1024 / 1024)
    }
}
