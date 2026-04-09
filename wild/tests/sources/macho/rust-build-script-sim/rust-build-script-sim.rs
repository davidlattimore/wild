//#LinkerDriver:clang

// Simulates what proc-macro2's build script does: run a subprocess,
// capture output, parse strings, write to files. This exercises
// __const vtables, __data globals, __cstring literals, and GOT
// entries together under realistic conditions.

use std::collections::HashMap;
use std::io::Write;
use std::process::Command;

fn probe_rustc_version() -> Option<u32> {
    let output = Command::new("rustc")
        .arg("--version")
        .output()
        .ok()?;
    let stdout = String::from_utf8(output.stdout).ok()?;
    // Parse "rustc 1.XX.Y (...)"
    let version = stdout.split(' ').nth(1)?;
    let minor = version.split('.').nth(1)?;
    minor.parse().ok()
}

fn build_feature_map(version: u32) -> HashMap<String, bool> {
    let mut features = HashMap::new();
    features.insert("proc_macro".to_string(), version >= 30);
    features.insert("span_locations".to_string(), version >= 45);
    features.insert("literal_c_string".to_string(), version >= 77);
    features.insert("source_text".to_string(), version >= 80);
    features.insert("is_available".to_string(), version >= 71);
    features
}

fn write_output(features: &HashMap<String, bool>) -> std::io::Result<()> {
    let mut buf = Vec::new();
    for (name, enabled) in features {
        if *enabled {
            writeln!(buf, "cargo:rustc-cfg={name}")?;
        }
    }
    // Just verify we can produce output, don't actually write to cargo
    assert!(!buf.is_empty());
    Ok(())
}

fn main() {
    let version = probe_rustc_version().unwrap_or(0);
    assert!(version > 50, "rustc version too old: {version}");

    let features = build_feature_map(version);
    assert!(features.len() == 5);
    assert!(*features.get("proc_macro").unwrap());

    write_output(&features).expect("write failed");

    // Exercise format strings and dynamic allocation
    let msgs: Vec<String> = (0..100)
        .map(|i| format!("cargo:rustc-check-cfg=cfg(feature_{i})"))
        .collect();
    assert_eq!(msgs.len(), 100);
    assert!(msgs[42].contains("feature_42"));

    std::process::exit(42);
}
