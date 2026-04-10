//! Test runner for sold (bluewhalesystems/sold) Mach-O shell tests.
//!
//! These tests are adapted from the sold linker's Mach-O test suite (MIT License).
//!
//! Each test is a bash script that compiles C/C++ code, links with the linker
//! under test (via `--ld-path=./ld64`), and verifies the output.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn wild_binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wild"))
}

fn sold_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/sold-macho")
}

fn collect_tests(tests: &mut Vec<libtest_mimic::Trial>) {
    let wild_bin = wild_binary_path();
    let test_dir = sold_tests_dir();

    // Create a working directory with ld64 symlink
    let work_dir = std::env::temp_dir().join("wild-sold-tests");
    std::fs::create_dir_all(&work_dir).unwrap();
    let ld64_link = work_dir.join("ld64");
    let _ = std::fs::remove_file(&ld64_link);
    std::os::unix::fs::symlink(&wild_bin, &ld64_link).unwrap();

    for entry in std::fs::read_dir(&test_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().map_or(true, |e| e != "sh") {
            continue;
        }

        let test_name = path.file_stem().unwrap().to_string_lossy().to_string();
        let test_path = path.clone();
        let wd = work_dir.clone();

        let ignored = should_ignore(&test_name);

        tests.push(
            libtest_mimic::Trial::test(format!("sold-macho/{test_name}"), move || {
                run_sold_test(&test_path, &wd).map_err(Into::into)
            })
            .with_ignored_flag(ignored),
        );
    }
}

fn should_ignore(name: &str) -> bool {
    // Tests that don't use --ld-path (invoke ./ld64 directly without cc)
    const DIRECT_LD64: &[&str] = &[];

    // Tests that use flags/features Wild doesn't support yet
    const UNSUPPORTED_FLAGS: &[&str] = &[
        "flat-namespace",         // -flat_namespace
        "undefined",              // -undefined warning
        "U",                      // -U (dynamic lookup)
        "umbrella",               // -umbrella
        "application-extension",  // -application_extension
        "application-extension2", // -application_extension
        // exported-symbols-list now passes (export trie filtering via export_list)
        // unexported-symbols-list now passes (unexport_list filtering)
        "export-dynamic", // -export_dynamic
        "merge-scope",    // visibility merging
        "hidden-l",       // -hidden-l
        // needed-l now passes (prefix link modifiers fall through to -l logic)
        "needed-framework", // -needed_framework
        "weak-l",           // -weak-l
        // reexport-l now passes (recursive LC_REEXPORT_DYLIB chain tracing)
        "reexport-library", // -reexport_library
        // install-name now passes (-install_name support)
        "install-name-executable-path", // @executable_path
        "install-name-loader-path",     // @loader_path
        "install-name-rpath",           // @rpath
        // rpath now passes (-rpath → LC_RPATH)
        // search-paths-first now passes (default search order is paths-first)
        "search-dylibs-first", // -search_dylibs_first (needs opposite search order)
        "sectcreate",          // -sectcreate
        "order-file",          // -order_file
        // stack-size now passes
        "map",                // -map
        "dependency-info",    // -dependency_info
        "print-dependencies", // -print_dependency_info
        // macos-version-min now passes
        // platform-version now passes
        // S now passes (stab debug symbol pass-through + -S strip)
        // strip now passes (LINKEDIT packing + linker-signed codesign)
        // no-function-starts now passes
        // data-in-code-info now passes
        "subsections-via-symbols", // -subsections_via_symbols
        "add-ast-path",            // -add_ast_path
        // add-empty-section now passes
        // pagezero-size2 now passes (error when used with -dylib)
        // oso-prefix now passes (-oso_prefix with canonicalized OSO paths)
        "start-stop-symbol", /* __start_/__stop_ sections
                           * framework now passes (-F/-framework support) */
    ];

    // Tests requiring LTO
    const LTO: &[&str] = &["lto", "lto-dead-strip-dylibs", "object-path-lto"];

    // Tests that need linking against a .dylib
    const NEEDS_DYLIB_INPUT: &[&str] = &[
        // dylib now passes (dylib input consumption)
        "tls-dylib", // TLS across dylibs
        // data-reloc now passes
        "fixup-chains-addend",   // links dylib + object (fixup chains)
        "fixup-chains-addend64", // links dylib + object (fixup chains)
        // weak-def-dylib now passes
        "mark-dead-strippable-dylib", // links against dylib (dead_strip_dylibs)
    ];

    // Validation/correctness bugs in Wild to fix
    const WILD_BUGS: &[&str] = &[
        "tls",           // TLV descriptor offset validation
        "tls-mismatch",  // TLS type mismatch errors
        "tls-mismatch2", // TLS type mismatch errors
        // cstring now passes (S_CSTRING_LITERALS merge enabled)
        // duplicate-error now passes (error format matches sold)
        // missing-error now passes (error format matches sold)
        "undef",                           // undefined symbol handling
        "fixup-chains-unaligned-error",    // unaligned fixup error
        "exception-in-static-initializer", // init func exceptions
        "indirect-symtab",                 // indirect symbol table
        "init-offsets",                    // __mod_init_func offsets
        "init-offsets-fixup-chains",       // init offsets + fixup chains
        "literals",                        // literal section merging
        "libunwind",                       // libunwind integration
        "objc-selector",                   // ObjC selector refs
        "debuginfo",                       // debug info pass-through
    ];

    // x86_64-specific tests
    const X86_ONLY: &[&str] = &[];

    // Tests that invoke ld64 directly (not through cc --ld-path)
    const NO_LD_PATH: &[&str] = &[];

    // .tbd parsing — all pass
    const TBD: &[&str] = &[];

    // Load command / output format checks
    const OUTPUT_FORMAT: &[&str] = &[
        "lc-build-version", // LC_BUILD_VERSION tool field
        // uuid now passes (-final_output, -no_uuid, -random_uuid)
        // uuid2 now passes
        "version", // -current_version / -compatibility_version
        "w",       // -w (needs -application_extension warning)
        // Z now passes (-Z no default search paths)
        // adhoc-codesign now passes (linker-signed + no_adhoc_codesign flag)
        "dead-strip-dylibs",  // -dead_strip_dylibs
        "dead-strip-dylibs2", // -dead_strip_dylibs
    ];

    DIRECT_LD64.contains(&name)
        || UNSUPPORTED_FLAGS.contains(&name)
        || LTO.contains(&name)
        || WILD_BUGS.contains(&name)
        || X86_ONLY.contains(&name)
        || NO_LD_PATH.contains(&name)
        || NEEDS_DYLIB_INPUT.contains(&name)
        || TBD.contains(&name)
        || OUTPUT_FORMAT.contains(&name)
}

fn run_sold_test(test_path: &Path, work_dir: &Path) -> Result<(), String> {
    let output = Command::new("bash")
        .arg(test_path)
        .current_dir(work_dir)
        .env("WILD_VALIDATE_OUTPUT", "1")
        .output()
        .map_err(|e| format!("bash: {e}"))?;

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let mut msg = format!("Test failed with status {}\n", output.status);
        if !stdout.is_empty() {
            msg.push_str(&format!("stdout:\n{stdout}\n"));
        }
        if !stderr.is_empty() {
            msg.push_str(&format!("stderr:\n{stderr}\n"));
        }
        return Err(msg);
    }

    Ok(())
}

fn main() {
    let mut tests = Vec::new();
    collect_tests(&mut tests);
    let args = libtest_mimic::Arguments::from_args();
    libtest_mimic::run(&args, tests).exit();
}
