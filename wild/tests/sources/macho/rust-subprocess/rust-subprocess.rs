//#LinkerDriver:clang

// Tests that string formatting, env vars, and subprocess execution work.
// This exercises __const, __data, __cstring, and GOT entries together —
// similar to what proc-macro2's build script does.

use std::env;
use std::process::Command;

fn main() {
    // String formatting exercises __const vtables and __cstring data.
    let msg = format!("hello {} world", 42);
    assert_eq!(msg, "hello 42 world");

    // Env var access exercises libc GOT entries.
    env::set_var("WILD_TEST_VAR", "test_value");
    let val = env::var("WILD_TEST_VAR").unwrap();
    assert_eq!(val, "test_value");

    // Subprocess execution exercises many sections together.
    let output = Command::new("echo")
        .arg("hi")
        .output()
        .expect("failed to run echo");
    assert!(output.status.success());

    std::process::exit(42);
}
