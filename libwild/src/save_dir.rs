//! Support for saving inputs for later use.

use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_kind::FileKind;
use foldhash::HashMap as FoldHashMap;
use foldhash::HashMapExt as _;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

pub(crate) struct SaveDir(Option<SaveDirState>);

const SAVE_DIR_ENV: &str = "WILD_SAVE_DIR";
const SAVE_BASE_ENV: &str = "WILD_SAVE_BASE";
const SKIP_LINKING_ENV: &str = "WILD_SAVE_SKIP_LINKING";

const PRELUDE: &str = include_str!("save-dir-prelude.sh");

struct SaveDirState {
    dir: PathBuf,
    copied_paths: FoldHashMap<String, PathBuf>,
    args: Vec<String>,
}

impl SaveDir {
    pub(crate) fn new<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(
        args: &F,
    ) -> Result<Self> {
        let Some(dir) = save_dir_from_env()? else {
            return Ok(Self(None));
        };

        Ok(Self(Some(SaveDirState::new(
            dir,
            args().map(|s| s.as_ref().to_owned()).collect(),
        ))))
    }

    pub(crate) fn finish(&self) -> Result {
        if let Some(state) = self.0.as_ref() {
            state.finish()?;
        }
        Ok(())
    }

    pub(crate) fn handle_file(&mut self, arg: &str) -> Result {
        if let Some(state) = self.0.as_mut() {
            state.handle_file(arg)?;
        }
        Ok(())
    }
}

fn save_dir_from_env() -> Result<Option<PathBuf>> {
    if let Ok(d) = std::env::var(SAVE_DIR_ENV) {
        let dir = PathBuf::from(d);

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

        return Ok(Some(dir));
    }

    if let Ok(d) = std::env::var(SAVE_BASE_ENV) {
        let base = PathBuf::from(d);
        std::fs::create_dir_all(&base).with_context(|| {
            format!(
                "Failed to create directory `{}` specified by {SAVE_BASE_ENV}",
                base.display()
            )
        })?;

        let mut counter = 0;

        loop {
            let subdir = base.join(counter.to_string());
            if std::fs::create_dir(&subdir).is_ok() {
                return Ok(Some(subdir));
            }
            counter += 1;
        }
    } else {
        Ok(None)
    }
}

impl SaveDirState {
    fn new(dir: PathBuf, args: Vec<String>) -> Self {
        SaveDirState {
            dir,
            copied_paths: FoldHashMap::new(),
            args,
        }
    }

    fn finish(&self) -> Result {
        let run_with_file = self.dir.join("run-with");
        self.write_args_file(&run_with_file)
            .with_context(|| format!("Failed to write `{}`", run_with_file.display()))?;
        if std::env::var(SKIP_LINKING_ENV).is_ok() {
            std::process::exit(0);
        }
        Ok(())
    }

    fn write_args_file(&self, run_file: &Path) -> Result {
        let mut file = std::fs::File::create(run_file)?;
        let mut out = BufWriter::new(&mut file);
        out.write_all(PRELUDE.as_bytes())?;
        self.write_args(&mut out)?;
        drop(out);
        crate::fs::make_executable(&file)?;
        Ok(())
    }

    fn write_args(&self, out: &mut BufWriter<&mut std::fs::File>) -> Result {
        let mut is_output_file = false;
        let mut original_output_file = None;

        for arg in &self.args {
            out.write_all(b" \\\n  ")?;

            if is_output_file {
                out.write_all(b"$OUT")?;
                is_output_file = false;
                original_output_file = Some(arg);
                continue;
            }

            is_output_file = arg == "-o";

            let maybe_path = if let Some(eq_index) = arg.find('=') {
                out.write_all(&arg.as_bytes()[..=eq_index])?;
                &arg[eq_index + 1..]
            } else {
                arg.as_str()
            };

            if let Some(copied) = self.copied_paths.get(maybe_path) {
                write_copied_file_arg(out, copied)?;
            } else {
                for b in maybe_path.bytes() {
                    if b" $\\".contains(&b) {
                        out.write_all(b"\\")?;
                    }
                    out.write_all(&[b])?;
                }
            }
        }

        if let Some(orig) = original_output_file {
            out.write_all(b"\n# Original output file: ")?;
            out.write_all(orig.as_bytes())?;
        }
        Ok(())
    }

    /// To save disk space, we first attempt to hard link the file. If that fails, then just
    /// copy it. Returns where we copied the file to.
    fn copy_file(&self, source_path: &PathBuf) -> Result<PathBuf> {
        let dest_path = unique_dest_path(&self.dir, source_path)?;

        copy_file_to(source_path, &dest_path)?;

        Ok(dest_path)
    }

    fn handle_file(&mut self, arg: &str) -> Result {
        let source_path = std::fs::canonicalize(Path::new(arg))?;

        if source_path.is_dir() || self.copied_paths.contains_key(arg) {
            return Ok(());
        }

        let file_bytes = std::fs::read(&source_path)?;
        let file_kind = FileKind::identify_bytes(&file_bytes)?;
        if file_kind == FileKind::ThinArchive {
            self.handle_thin_archive(&source_path, &file_bytes)?;
        }

        let copied = self.copy_file(&source_path)?;

        self.copied_paths.insert(arg.to_owned(), copied);

        Ok(())
    }

    fn handle_thin_archive(&self, path: &Path, file_bytes: &[u8]) -> Result {
        let parent_path = path.parent().unwrap();
        let mut extended_filenames = None;

        for entry in ArchiveIterator::from_archive_bytes(file_bytes)? {
            match entry? {
                ArchiveEntry::Filenames(t) => extended_filenames = Some(t),
                ArchiveEntry::Thin(entry) => {
                    let entry_path = entry.identifier(extended_filenames).as_path();
                    if entry_path.is_absolute() {
                        bail!(
                            "Thin archive `{}` contained absolute path `{}`",
                            path.display(),
                            entry_path.display()
                        );
                    }
                    let absolute_entry_path = parent_path.join(entry_path);

                    if let Some(relative_dir) = entry_path.parent() {
                        let directory = self.dir.join(relative_dir);
                        std::fs::create_dir_all(&directory).with_context(|| {
                            format!("Failed to create directory `{}`", directory.display())
                        })?;
                    }

                    let dest_path = self.dir.join(entry_path);
                    copy_file_to(&absolute_entry_path, &dest_path)?;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

fn copy_file_to(source_path: &PathBuf, dest_path: &PathBuf) -> Result<(), crate::error::Error> {
    if std::fs::hard_link(source_path, dest_path).is_err() {
        std::fs::copy(source_path, dest_path).with_context(|| {
            format!(
                "Failed to copy `{}` to `{}`",
                source_path.display(),
                dest_path.display()
            )
        })?;
    }

    Ok(())
}

fn write_copied_file_arg(out: &mut BufWriter<&mut std::fs::File>, path: &Path) -> Result {
    let file_name = path.file_name().context("Invalid copied file name")?;
    out.write_all(b"$D/")?;
    out.write_all(file_name.as_encoded_bytes())?;
    Ok(())
}

/// Return the full path to a new filename in `dir` that if possible has the same filename as that
/// of `path`.
fn unique_dest_path(dir: &Path, path: &Path) -> Result<PathBuf> {
    let file_name = path.file_name().context("Missing file_name")?;
    let raw_dest_path = dir.join(file_name);
    let mut result = raw_dest_path.clone();
    let mut seq = 0;
    while result.exists() {
        result = sequence_path(&raw_dest_path, seq)
            .with_context(|| format!("Invalid path `{}`", raw_dest_path.display()))?;

        seq += 1;
    }
    Ok(result)
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
