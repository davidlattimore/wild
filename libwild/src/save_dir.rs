//! Support for saving inputs for later use.

use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::args::Modifiers;
use crate::bail;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::FileData;
use crate::linker_script::LinkerScript;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

#[derive(Debug, Default)]
pub(crate) struct SaveDir(Option<SaveDirState>);

const SAVE_DIR_ENV: &str = "WILD_SAVE_DIR";
const SAVE_BASE_ENV: &str = "WILD_SAVE_BASE";
const SKIP_LINKING_ENV: &str = "WILD_SAVE_SKIP_LINKING";

const PRELUDE: &str = include_str!("save-dir-prelude.sh");

#[derive(Debug)]
struct SaveDirState {
    dir: PathBuf,
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

    pub(crate) fn finish<'a, I: Iterator<Item = &'a PathBuf>>(&self, filenames: I) -> Result {
        if let Some(state) = self.0.as_ref() {
            state.finish(filenames)?;
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
        SaveDirState { dir, args }
    }

    /// Finalise the save directory. Makes sure that all `filenames` have been copied, writes the
    /// `run-with` file and if the environment variable is set to indicate that we should skip
    /// linking, then exit.
    fn finish<'a, I: Iterator<Item = &'a PathBuf>>(&self, filenames: I) -> Result {
        for filename in filenames {
            self.copy_file(&std::path::absolute(filename)?)?;
        }

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
        let mut original_output_file = None;
        let mut args = self.args.iter();

        while let Some(arg) = args.next() {
            out.write_all(b" \\\n  ")?;

            if let Some(mut path) = arg.strip_prefix("-o") {
                if path.is_empty() {
                    path = args.next().map(|s| s.as_str()).unwrap_or_default();
                }
                out.write_all(b"-o $OUT")?;
                original_output_file = Some(path);
            } else if let Some(mut dir) = arg.strip_prefix("-L") {
                if dir.is_empty() {
                    dir = args.next().map(|s| s.as_str()).unwrap_or_default();
                }

                let dir = std::path::absolute(dir)?;
                out.write_all(b"-L")?;
                write_copied_file_arg(out, &dir)?;
            } else {
                let maybe_path = if let Some(eq_index) = arg.find('=') {
                    out.write_all(&arg.as_bytes()[..=eq_index])?;
                    &arg[eq_index + 1..]
                } else {
                    arg.as_str()
                };

                let path = std::path::absolute(maybe_path)?;
                if self.output_path(&path).exists() {
                    write_copied_file_arg(out, &path)?;
                } else {
                    for b in maybe_path.bytes() {
                        if b" $\\".contains(&b) {
                            out.write_all(b"\\")?;
                        }
                        out.write_all(&[b])?;
                    }
                }
            }
        }

        if let Some(orig) = original_output_file {
            out.write_all(b"\n# Original output file: ")?;
            out.write_all(orig.as_bytes())?;
        }
        Ok(())
    }

    fn output_path(&self, path: &Path) -> PathBuf {
        self.dir.join(to_output_relative_path(path))
    }

    /// Copies `source_path` to our output directory.
    fn copy_file(&self, source_path: &Path) -> Result {
        let dest_path = self.output_path(source_path);

        if dest_path.exists() {
            return Ok(());
        }

        // The parent directory might be an actual directory or it might be a symlink. Either way,
        // we want to copy it before we copy our file.
        if let Some(parent) = source_path.parent() {
            self.copy_file(parent)?;
        }

        // We need to check again if `dest_path` exists because paths containing ".." mean that
        // creating the parent of `dest_path` might actually have created `dest_path`.
        if dest_path.exists() {
            return Ok(());
        }

        let meta = std::fs::symlink_metadata(source_path)
            .with_context(|| format!("Failed to read metadata for `{}`", source_path.display()))?;

        if meta.is_dir() {
            std::fs::create_dir(&dest_path)
                .with_context(|| format!("Failed to create directory `{}`", dest_path.display()))?;
        } else if meta.is_symlink() {
            let directory = source_path.parent().context("Invalid path")?;
            let mut target = std::fs::read_link(source_path)
                .with_context(|| format!("Failed to read symlink `{}`", source_path.display()))?;

            if target.is_absolute() {
                self.copy_file(&target)?;
                target = make_relative_path(&target, directory);
            } else {
                let absolute_target = directory.join(&target);
                self.copy_file(&absolute_target)?;
            }

            std::os::unix::fs::symlink(&target, &dest_path).with_context(|| {
                format!(
                    "Failed to symlink {} to {}",
                    dest_path.display(),
                    target.display()
                )
            })?;
        } else {
            if let Ok(data) = FileData::new(source_path, false) {
                match FileKind::identify_bytes(&data) {
                    Ok(FileKind::ThinArchive) => self.handle_thin_archive(source_path)?,
                    Ok(FileKind::Text) => {
                        // We don't want to prevent the save-dir mechanism from working just because
                        // we failed to parse a linker script, so in case of failure, we fall
                        // through to just copying the file as-is.
                        if let Ok(updated_bytes) = make_linker_script_relative(&data, source_path) {
                            std::fs::write(dest_path, updated_bytes)?;
                            return Ok(());
                        }
                    }
                    _ => {}
                }
            }

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
        }

        Ok(())
    }

    fn handle_file(&self, arg: &str) -> Result {
        let path = std::path::absolute(Path::new(arg))?;
        if std::fs::exists(&path).is_ok_and(|exists| exists) {
            self.copy_file(&path)
        } else {
            Ok(())
        }
    }

    /// Copies the files listed by the thin archive.
    fn handle_thin_archive(&self, path: &Path) -> Result {
        let file_bytes = std::fs::read(path)?;
        let parent_path = path.parent().unwrap();
        let mut extended_filenames = None;

        for entry in ArchiveIterator::from_archive_bytes(&file_bytes)? {
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

                    self.copy_file(&absolute_entry_path)?;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

fn make_linker_script_relative(bytes: &[u8], source_path: &Path) -> Result<Vec<u8>> {
    let script = LinkerScript::parse(bytes, source_path)?;

    let mut absolute_paths = Vec::new();
    script.foreach_input(Modifiers::default(), |input| {
        if let crate::args::InputSpec::File(path) = input.spec
            && path.is_absolute()
        {
            absolute_paths.push(path);
        }

        Ok(())
    })?;

    let mut text = String::from_utf8(bytes.to_owned())?;

    let script_dir = source_path.parent().context("Invalid path")?;

    for path in absolute_paths {
        let relative_path = make_relative_path(&path, script_dir);
        let relative_str = relative_path.to_str().context("Path isn't valid UTF-8")?;
        let path_str = path.to_str().context("Path isn't valid UTF-8")?;
        text = text.replace(path_str, relative_str);
    }

    Ok(text.into_bytes())
}

/// Returns a relative path to reach `target` from `directory`. Both should be absolute paths.
fn make_relative_path(target: &Path, directory: &Path) -> PathBuf {
    assert!(target.is_absolute());
    assert!(directory.is_absolute());
    let mut out = PathBuf::new();
    let mut p = directory;

    // If `target` and `directory` share some common prefix, then our path may not be as short as
    // possible, but it should still work.
    while let Some(parent) = p.parent() {
        out.push("..");
        p = parent;
    }

    out.extend(target.iter());

    out
}

fn write_copied_file_arg(out: &mut BufWriter<&mut std::fs::File>, path: &Path) -> Result {
    out.write_all(b"$D/")?;
    out.write_all(to_output_relative_path(path).as_os_str().as_encoded_bytes())?;
    Ok(())
}

/// Returns where we should copy `path` to when we put it in our output directory.
fn to_output_relative_path(path: &Path) -> PathBuf {
    path.iter()
        .filter(|p| p.as_encoded_bytes() != b"/")
        .collect()
}
