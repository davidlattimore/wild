//! Support for saving inputs for later use.

use crate::error::Result;
use ahash::AHashMap;
use anyhow::Context;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

pub(crate) struct SaveDir {
    dir: Option<PathBuf>,
    copied_paths: AHashMap<String, String>,
}

const SAVE_DIR_ENV: &str = "WILD_SAVE_DIR";
const SAVE_BASE_ENV: &str = "WILD_SAVE_BASE";

const PRELUDE: &str = include_str!("save-dir-prelude.sh");

impl SaveDir {
    pub(crate) fn new() -> Result<Self> {
        if let Ok(dir) = std::env::var(SAVE_DIR_ENV) {
            let dir = PathBuf::from(dir);
            if dir.exists() {
                std::fs::remove_dir_all(&dir).with_context(|| {
                    format!(
                        "Failed to delete `{}`. If you're running multiple link commands \
                         concurrently, try using {} instead.",
                        dir.display(),
                        SAVE_BASE_ENV
                    )
                })?;
            }
            std::fs::create_dir_all(&dir).with_context(|| {
                format!(
                    "Failed to create directory `{}` specified by {SAVE_DIR_ENV}",
                    dir.display()
                )
            })?;
            return Ok(Self::with_dir(Some(dir)));
        }
        if let Ok(dir) = std::env::var(SAVE_BASE_ENV) {
            let dir = PathBuf::from(dir);
            std::fs::create_dir_all(&dir).with_context(|| {
                format!(
                    "Failed to create directory `{}` specified by {SAVE_BASE_ENV}",
                    dir.display()
                )
            })?;
            let mut counter = 0;
            loop {
                let subdir = dir.join(counter.to_string());
                if std::fs::create_dir(&subdir).is_ok() {
                    return Ok(Self::with_dir(Some(subdir)));
                }
                counter += 1;
            }
        }
        Ok(Self::with_dir(None))
    }

    fn with_dir(dir: Option<PathBuf>) -> Self {
        SaveDir {
            dir,
            copied_paths: AHashMap::new(),
        }
    }

    pub(crate) fn finish(&self) -> Result {
        let Some(dir) = self.dir.as_ref() else {
            return Ok(());
        };
        let run_with_file = dir.join("run-with");
        self.write_args_file(&run_with_file)
            .with_context(|| format!("Failed to write `{}`", run_with_file.display()))
    }

    fn write_args_file(&self, run_file: &Path) -> Result {
        let mut file = std::fs::File::create(run_file)?;
        let mut out = BufWriter::new(&mut file);
        let mut args = std::env::args();
        out.write_all(PRELUDE.as_bytes())?;
        args.next();
        self.write_args(args, &mut out)?;
        drop(out);
        crate::fs::make_executable(&file)?;
        Ok(())
    }

    fn write_args(&self, args: std::env::Args, out: &mut BufWriter<&mut std::fs::File>) -> Result {
        let mut is_output_file = false;
        let mut original_output_file = None;
        for arg in args {
            out.write_all(" \\\n  ".as_bytes())?;
            if is_output_file {
                out.write_all(b"$OUT")?;
                is_output_file = false;
                original_output_file = Some(arg);
                continue;
            }
            is_output_file = arg == "-o";
            if let Some(copied) = self.copied_paths.get(&arg) {
                out.write_all(b"$D/")?;
                out.write_all(copied.as_bytes())?;
            } else {
                out.write_all(arg.as_bytes())?;
            }
        }
        if let Some(orig) = original_output_file {
            out.write_all(b"\n# Original output file: ")?;
            out.write_all(orig.as_bytes())?;
        }
        Ok(())
    }

    pub(crate) fn handle_file(&mut self, arg: &str) -> Result {
        let Some(dir) = self.dir.as_ref() else {
            return Ok(());
        };
        let source_path = Path::new(arg);
        if let Some(dest_path) = unique_dest_path(dir, source_path) {
            // To save disk space, we first attempt to hard link the file. If that fails, then just
            // copy it.
            if std::fs::hard_link(source_path, &dest_path).is_err() {
                std::fs::copy(source_path, &dest_path).with_context(|| {
                    format!(
                        "Failed to copy `{}` to `{}`",
                        source_path.display(),
                        dest_path.display()
                    )
                })?;
            }
            self.copied_paths.insert(
                arg.to_owned(),
                dest_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .context("Path is not valid UTF-8")?
                    .to_owned(),
            );
        }

        Ok(())
    }
}

/// Return the full path to a new filename in `dir` that if possible has the same filename as that
/// of `path`.
fn unique_dest_path(dir: &Path, path: &Path) -> Option<PathBuf> {
    let file_name = path.file_name()?;
    let raw_dest_path = dir.join(file_name);
    let mut result = raw_dest_path.clone();
    let mut seq = 0;
    while result.exists() {
        if let Some(n) = sequence_path(&raw_dest_path, seq) {
            result = n;
        } else {
            return None;
        }
        seq += 1;
    }
    Some(result)
}

fn sequence_path(path: &Path, sequence: i32) -> Option<PathBuf> {
    let stem = path.file_stem()?;
    let dir = path.parent()?;
    let extension = path.extension()?;
    let mut out = stem.to_owned();
    out.push(format!(".{sequence}."));
    out.push(extension);
    Some(dir.join(out))
}

#[test]
fn test_sequence_path() {
    assert_eq!(
        sequence_path(Path::new("/foo/bar/libx.o"), 7),
        Some(PathBuf::from("/foo/bar/libx.7.o"))
    );
}
