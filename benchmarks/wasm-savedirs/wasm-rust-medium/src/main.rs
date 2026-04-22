//! Synthetic medium-size rust → wasm workload for the wild bench
//! matrix.
//!
//! Goal is to produce ~1-2 MB of wasm32-wasip2 output that exercises
//! a representative cross-section of the linker's work:
//!   - `regex` pulls in non-trivial generic code (DFA, syntax tree).
//!   - `serde_json` pulls in lots of monomorphised Visitor impls.
//!   - `sha2` is a tight compute kernel.
//!
//! The binary itself is throwaway — the bench harness measures
//! how long wild takes to LINK the rustc-produced .o set, not how
//! long the binary takes to run. We just need the object set to
//! exist on disk after `cargo build --release --target wasm32-wasip2`.

use sha2::{Digest, Sha256};

fn main() {
    // Synthetic workload to keep the compiler from dead-code-stripping
    // anything we care about. The actual output is irrelevant.
    let input = std::env::args().nth(1).unwrap_or_else(|| "wild benchmark".to_string());
    let pattern = std::env::args().nth(2).unwrap_or_else(|| r"\b\w{4,12}\b".to_string());

    let re = regex::Regex::new(&pattern).expect("regex compiles");
    let words: Vec<&str> = re.find_iter(&input).map(|m| m.as_str()).collect();

    let json = serde_json::json!({
        "input": &input,
        "pattern": &pattern,
        "matches": &words,
        "match_count": words.len(),
    });

    let mut hasher = Sha256::new();
    hasher.update(json.to_string().as_bytes());
    let digest = hasher.finalize();

    println!("{} matches, sha256={:x}", words.len(), digest);
}
