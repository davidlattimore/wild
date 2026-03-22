use libwild::bail;
use libwild::error::Context as _;
use std::env;
use std::fs::read_dir;
use std::path::Path;
use std::process::Command;
use std::process::Stdio;

type Result<T = (), E = libwild::error::Error> = core::result::Result<T, E>;

#[test]
fn check_sources_format() {
    if std::env::var_os("WILD_TEST_IGNORE_FORMAT").is_some() {
        return;
    }

    let extensions = ["c", "cc", "h"];
    let sources_path = format!("{}/tests/sources", env!("CARGO_MANIFEST_DIR"));
    let files_iter = read_dir(&sources_path).unwrap().filter_map(|entry| {
        let path = entry.as_ref().unwrap().path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|extension| extensions.contains(&extension.to_str().unwrap()))
        {
            Some(path)
        } else {
            None
        }
    });

    let clang_format_out = Command::new("clang-format")
        .arg("--dry-run")
        .arg("-Werror")
        // Undocumented option that forces the colours: https://github.com/llvm/llvm-project/issues/119224
        .arg("--color")
        .args(files_iter)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn `clang-format`, is it installed?");

    if !clang_format_out.status.success() {
        let stdout = String::from_utf8_lossy(&clang_format_out.stdout);
        let stderr = String::from_utf8_lossy(&clang_format_out.stderr);
        let mut out = String::with_capacity(stdout.len() + stderr.len() + 1);
        if !stdout.is_empty() {
            out.push_str(&stdout);
            if !stderr.is_empty() {
                out.push('\n');
            }
        }
        if !stderr.is_empty() {
            out.push_str(&stderr);
        }
        let clang_out = Command::new("clang-format")
            .arg("--version")
            .output()
            .expect("Failed to spawn `clang-format --version`");
        let clang_version = String::from_utf8_lossy(&clang_out.stdout);
        let version_no_endline = clang_version.trim_end_matches('\n');
        panic!(
            "clang-format ({version_no_endline}) check failed:\n{out}\nRun `clang-format -i {sources_path}/*.{{{extensions_str}}}` to fix it.",
            extensions_str = extensions.join(",")
        )
    }
}

#[test]
fn check_text_files() -> Result {
    const EXCLUDE_DIR: &[&str] = &[
        "target",
        "build",
        "external_test_suites",
        "fakes-debug",
        "fakes",
    ];

    fn verify_path(path: &Path, problems: &mut Vec<String>) -> Result {
        if EXCLUDE_DIR.iter().any(|e| path.ends_with(e)) {
            return Ok(());
        }

        if path.is_dir() {
            for entry in read_dir(path)
                .with_context(|| format!("Failed to read directory {}", path.display()))?
            {
                let entry = entry?;
                let file_name = entry.file_name();
                let Some(file_name) = file_name.to_str() else {
                    continue;
                };

                // Ignore hidden files / directories.
                if file_name.starts_with('.') {
                    continue;
                }

                verify_path(&entry.path(), problems)?;
            }
        } else if path.is_symlink() {
            // Ignore symlinks.
        } else {
            let content = std::fs::read(path)
                .with_context(|| format!("Failed to read file {}", path.display()))?;

            let is_valid_utf8 = std::str::from_utf8(&content).is_ok();
            let is_text = is_valid_utf8 && !content.contains(&0);

            if is_text {
                if content.contains(&b'\r') {
                    problems.push(format!(
                        "The file {} uses Windows line-endings. Please convert it to Unix-style.",
                        path.display()
                    ));
                }

                let allow_no_trailing_newline =
                    content.is_empty() || path.extension().is_some_and(|ext| ext == "json");

                if !allow_no_trailing_newline && !content.ends_with(b"\n") {
                    problems.push(format!(
                        "The file {} is missing a trailing newline",
                        path.display()
                    ));
                }
            }
        }
        Ok(())
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();

    let mut problems = Vec::new();
    verify_path(root, &mut problems)?;

    if !problems.is_empty() {
        bail!("{}", problems.join("\n"))
    }

    Ok(())
}
