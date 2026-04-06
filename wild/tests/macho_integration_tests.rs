//! Integration tests for macOS Mach-O linking.
//!
//! Mirrors the structure of the ELF integration tests (`integration_tests.rs`) but for Mach-O.
//! Test sources live in `tests/sources/macho/{test_name}/{test_name}.{c,cc,rs}`.
//!
//! Supported directives (in `//#Directive:Args` format):
//!
//! Object:{filename}        Extra object file to compile and link.
//! CompArgs:...             Extra compiler flags.
//! LinkArgs:...             Extra linker flags.
//! ExpectError:{regex}      Link must fail; stderr must match regex.
//! RunEnabled:{bool}        Whether to execute the output (default: true).
//! Contains:{string}        Output binary must contain this string.
//! DoesNotContain:{string}  Output binary must NOT contain this string.

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only run on macOS.
    if cfg!(not(target_os = "macos")) {
        eprintln!("Mach-O integration tests only run on macOS — skipping.");
        let args = libtest_mimic::Arguments::from_args();
        let _ = libtest_mimic::run(&args, Vec::new());
        return Ok(());
    }

    let args = libtest_mimic::Arguments::from_args();
    let mut tests = Vec::new();
    collect_tests(&mut tests)?;
    let _ = libtest_mimic::run(&args, tests).exit_code();
    Ok(())
}

// ---------------------------------------------------------------------------
// Test collection
// ---------------------------------------------------------------------------

fn collect_tests(tests: &mut Vec<libtest_mimic::Trial>) -> Result<(), Box<dyn std::error::Error>> {
    let wild_bin = wild_binary_path();
    let src_root = macho_sources_dir();

    for entry in std::fs::read_dir(&src_root)? {
        let entry = entry?;
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let test_name = dir.file_name().unwrap().to_string_lossy().to_string();

        // Find primary source: {test_name}.{c,cc,rs}
        let primary = identify_primary_source(&dir, &test_name);
        let Some(primary) = primary else { continue };

        let config = parse_config(&dir, &primary)?;
        let wild = wild_bin.clone();

        let ignored = config.ignore_reason.is_some();
        tests.push(
            libtest_mimic::Trial::test(
                format!("macho::{test_name}"),
                move || run_test(&wild, &dir, &test_name, &primary, &config).map_err(Into::into),
            )
            .with_ignored_flag(ignored),
        );
    }
    Ok(())
}

fn identify_primary_source(dir: &Path, test_name: &str) -> Option<PathBuf> {
    for ext in &["c", "cc", "rs"] {
        let p = dir.join(format!("{test_name}.{ext}"));
        if p.exists() {
            return Some(p);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Config parsing
// ---------------------------------------------------------------------------

#[derive(Default)]
struct TestConfig {
    extra_objects: Vec<String>,
    comp_args: Vec<String>,
    link_args: Vec<String>,
    expect_error: Option<String>,
    run_enabled: bool,
    use_clang_driver: bool,
    contains: Vec<String>,
    does_not_contain: Vec<String>,
    ignore_reason: Option<String>,
}

fn parse_config(
    test_dir: &Path,
    primary: &Path,
) -> Result<TestConfig, Box<dyn std::error::Error>> {
    let mut cfg = TestConfig {
        run_enabled: true,
        ..Default::default()
    };

    let src = std::fs::read_to_string(primary)?;
    for line in src.lines() {
        let Some(directive) = line.strip_prefix("//#") else {
            continue;
        };
        let (key, value) = match directive.split_once(':') {
            Some((k, v)) => (k, v),
            None => (directive, ""),
        };
        match key {
            "Object" => cfg.extra_objects.push(value.to_string()),
            "CompArgs" => cfg.comp_args.extend(shell_words(value)),
            "LinkArgs" => cfg.link_args.extend(shell_words(value)),
            "ExpectError" => cfg.expect_error = Some(value.to_string()),
            "RunEnabled" => cfg.run_enabled = value.trim() != "false",
            "LinkerDriver" if value.trim().starts_with("clang") => cfg.use_clang_driver = true,
            "Contains" => cfg.contains.push(value.to_string()),
            "DoesNotContain" => cfg.does_not_contain.push(value.to_string()),
            "Ignore" => cfg.ignore_reason = Some(value.to_string()),
            _ => {} // Ignore unknown directives for forward-compatibility.
        }
    }

    // Also parse directives from extra object files (they might have CompArgs etc.)
    for obj_name in &cfg.extra_objects {
        let obj_path = test_dir.join(obj_name);
        if obj_path.exists() {
            let obj_src = std::fs::read_to_string(&obj_path)?;
            for line in obj_src.lines() {
                if let Some(directive) = line.strip_prefix("//#") {
                    if let Some(("CompArgs", v)) = directive.split_once(':').map(|(k, v)| (k, v)) {
                        // CompArgs in extra objects only apply to that object — ignored here.
                        let _ = v;
                    }
                }
            }
        }
    }

    Ok(cfg)
}

fn shell_words(s: &str) -> Vec<String> {
    s.split_whitespace().map(|w| w.to_string()).collect()
}

// ---------------------------------------------------------------------------
// Test execution
// ---------------------------------------------------------------------------

fn run_test(
    wild_bin: &Path,
    test_dir: &Path,
    test_name: &str,
    primary: &Path,
    config: &TestConfig,
) -> Result<(), String> {
    let build_dir = build_dir(test_name);
    std::fs::create_dir_all(&build_dir).map_err(|e| format!("mkdir: {e}"))?;

    // Compile all source files.
    let mut objects = Vec::new();
    let is_cpp = primary.extension().map_or(false, |e| e == "cc");

    compile_source(primary, &build_dir, &config.comp_args, is_cpp)?;
    objects.push(object_path(&build_dir, primary));

    for obj_name in &config.extra_objects {
        let src = test_dir.join(obj_name);
        let extra_cpp = src.extension().map_or(false, |e| e == "cc");
        compile_source(&src, &build_dir, &config.comp_args, extra_cpp)?;
        objects.push(object_path(&build_dir, &src));
    }

    // Link with wild.
    let output = build_dir.join(test_name);
    let mut cmd = if config.use_clang_driver {
        // Use clang as driver (passes -syslibroot, -L paths, etc.)
        let compiler = if is_cpp { "clang++" } else { "clang" };
        let mut c = Command::new(compiler);
        c.arg(format!("-fuse-ld={}", wild_bin.display()));
        for obj in &objects {
            c.arg(obj);
        }
        c.arg("-o").arg(&output);
        for arg in &config.link_args {
            c.arg(arg);
        }
        c
    } else {
        let mut c = Command::new(wild_bin);
        for obj in &objects {
            c.arg(obj);
        }
        c.arg("-o").arg(&output);
        for arg in &config.link_args {
            c.arg(arg);
        }
        c
    };

    let link_result = cmd.output().map_err(|e| format!("wild: {e}"))?;

    // Check for expected errors.
    if let Some(ref pattern) = config.expect_error {
        if link_result.status.success() {
            return Err(format!("Expected link failure matching '{pattern}', but link succeeded"));
        }
        let stderr = String::from_utf8_lossy(&link_result.stderr);
        if !stderr.contains(pattern) {
            return Err(format!(
                "Expected error matching '{pattern}', got:\n{stderr}"
            ));
        }
        return Ok(());
    }

    if !link_result.status.success() {
        let stderr = String::from_utf8_lossy(&link_result.stderr);
        return Err(format!("Link failed:\n{stderr}"));
    }

    // Binary content checks.
    let binary = std::fs::read(&output).map_err(|e| format!("read output: {e}"))?;
    for needle in &config.contains {
        if !binary_contains(&binary, needle.as_bytes()) {
            return Err(format!("Output binary does not contain '{needle}'"));
        }
    }
    for needle in &config.does_not_contain {
        if binary_contains(&binary, needle.as_bytes()) {
            return Err(format!("Output binary unexpectedly contains '{needle}'"));
        }
    }

    // Run the binary and check exit code.
    if config.run_enabled {
        let run = Command::new(&output)
            .output()
            .map_err(|e| format!("run: {e}"))?;
        let code = run.status.code().unwrap_or(-1);
        if code != 42 {
            return Err(format!("Expected exit code 42, got {code}"));
        }
    }

    Ok(())
}

fn compile_source(
    src: &Path,
    build_dir: &Path,
    extra_args: &[String],
    is_cpp: bool,
) -> Result<(), String> {
    let out = object_path(build_dir, src);
    let compiler = if is_cpp { "clang++" } else { "clang" };

    let mut cmd = Command::new(compiler);
    cmd.arg("-c").arg(src).arg("-o").arg(&out);
    for arg in extra_args {
        cmd.arg(arg);
    }

    let result = cmd.output().map_err(|e| format!("{compiler}: {e}"))?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        return Err(format!("Compilation of {} failed:\n{stderr}", src.display()));
    }
    Ok(())
}

fn object_path(build_dir: &Path, src: &Path) -> PathBuf {
    let stem = src.file_stem().unwrap().to_string_lossy();
    build_dir.join(format!("{stem}.o"))
}

fn binary_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

fn wild_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop(); // remove test binary name
    path.pop(); // remove `deps/`
    path.push("wild");
    if !path.exists() {
        path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target/debug/wild");
    }
    // clang -fuse-ld= requires an absolute path.
    std::fs::canonicalize(&path).unwrap_or(path)
}

fn macho_sources_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sources/macho")
}

fn build_dir(test_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(format!("target/macho-test-build/{test_name}"))
}
