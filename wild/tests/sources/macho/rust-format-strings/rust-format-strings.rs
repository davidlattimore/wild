//#LinkerDriver:clang

// Tests that Rust format strings and string constants are correctly linked
// when combined with thread-local storage. This exercises __const vtables,
// __cstring data, and __thread_vars alignment together.
// The proc-macro2 build script crashes because __thread_vars descriptors
// end up at a non-8-byte-aligned address.

use std::process::Command;
use std::ffi::OsString;
use std::env;

fn rustc_minor_version() -> Option<u32> {
    let rustc: OsString = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = std::str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}

fn main() {
    let version = rustc_minor_version().unwrap_or(0);
    if version > 50 {
        let msg = format!("rustc version: 1.{version}");
        assert!(msg.contains("rustc version:"), "format! corrupted: {msg:?}");
    }
    std::process::exit(42);
}
