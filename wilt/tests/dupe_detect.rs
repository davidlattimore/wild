//! Count byte-identical and "locally-renumbered-equivalent" function
//! bodies in wilt's output vs wasm-opt's output on /tmp/big.wasm.
//! Tells us how much of the 2 KB function-section gap is canonicalisable.

use std::collections::HashMap;
use std::process::Command;
use wilt::module::WasmModule;

fn sections_bodies<'a>(bytes: &'a [u8]) -> Vec<&'a [u8]> {
    let Ok(mut m) = WasmModule::parse(bytes) else {
        return Vec::new();
    };
    m.ensure_function_bodies_parsed();
    let data = m.data();
    m.function_bodies()
        .iter()
        .map(|b| b.body.slice(data))
        .collect()
}

/// Normalise local indices: rewrite every local.get/set/tee to use
/// indices in first-use order. Gives a canonical byte form that
/// catches "same code, different local permutation" near-duplicates.
fn canonical_body(body: &[u8]) -> Option<Vec<u8>> {
    use wilt::leb128;
    use wilt::opcode::InstrIter;
    use wilt::opcode::{self as opc};

    let start = opc::skip_locals(body)?;
    // Two passes: first assign canonical indices in first-use order,
    // then emit.
    let mut map: HashMap<u32, u32> = HashMap::new();
    let mut next_id: u32 = 0;
    let mut iter = InstrIter::new(body, start);
    while let Some((p, _)) = iter.next() {
        let op = body[p];
        if matches!(op, 0x20 | 0x21 | 0x22) {
            if let Some((idx, _)) = leb128::read_u32(&body[p + 1..]) {
                map.entry(idx).or_insert_with(|| {
                    let i = next_id;
                    next_id += 1;
                    i
                });
            }
        }
    }
    if iter.failed() {
        return None;
    }

    // Emit: locals header unchanged (the valtypes still live at original
    // positions; canonicalising locals would also need to reorder them,
    // but for dupe detection, just map the USE indices — equivalent
    // bodies pick the same canonical index for the same usage slot).
    let mut out = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..start]);
    let mut iter = InstrIter::new(body, start);
    let mut cursor = start;
    while let Some((p, len)) = iter.next() {
        out.extend_from_slice(&body[cursor..p]);
        let op = body[p];
        if matches!(op, 0x20 | 0x21 | 0x22) {
            if let Some((idx, _)) = leb128::read_u32(&body[p + 1..]) {
                if let Some(&new_idx) = map.get(&idx) {
                    out.push(op);
                    leb128::write_u32(&mut out, new_idx);
                    cursor = p + len;
                    continue;
                }
            }
        }
        out.extend_from_slice(&body[p..p + len]);
        cursor = p + len;
    }
    out.extend_from_slice(&body[cursor..]);
    Some(out)
}

fn dupe_stats(bytes: &[u8]) -> (usize, usize, usize) {
    let bodies = sections_bodies(bytes);
    let n = bodies.len();
    let mut raw_dupes: HashMap<&[u8], usize> = HashMap::new();
    for b in &bodies {
        *raw_dupes.entry(b).or_insert(0) += 1;
    }
    let raw_extra: usize = raw_dupes.values().map(|&c| c.saturating_sub(1)).sum();

    let mut canon_dupes: HashMap<Vec<u8>, usize> = HashMap::new();
    for b in &bodies {
        if let Some(c) = canonical_body(b) {
            *canon_dupes.entry(c).or_insert(0) += 1;
        }
    }
    let canon_extra: usize = canon_dupes.values().map(|&c| c.saturating_sub(1)).sum();

    (n, raw_extra, canon_extra)
}

fn wasm_opt(path: &str) -> Option<Vec<u8>> {
    let out = format!("/tmp/dupe_out_{}.wasm", std::process::id());
    let ok = Command::new("wasm-opt")
        .arg("-O")
        .arg(path)
        .arg("-o")
        .arg(&out)
        .arg("--enable-bulk-memory")
        .arg("--enable-sign-ext")
        .arg("--enable-nontrapping-float-to-int")
        .arg("--enable-mutable-globals")
        .arg("--enable-simd")
        .arg("--enable-reference-types")
        .arg("--enable-multivalue")
        .status()
        .ok()?
        .success();
    if !ok {
        return None;
    }
    let b = std::fs::read(&out).ok()?;
    let _ = std::fs::remove_file(&out);
    Some(b)
}

/// Count `call f` sites in a module grouped by f. Returns a map from
/// callee to number of direct call sites (defined bodies only).
fn count_callsites(bytes: &[u8]) -> HashMap<u32, u32> {
    use wilt::leb128;
    use wilt::opcode::InstrIter;
    use wilt::opcode::{self as opc};
    let Ok(mut m) = WasmModule::parse(bytes) else {
        return HashMap::new();
    };
    m.ensure_function_bodies_parsed();
    let data = m.data();
    let mut counts: HashMap<u32, u32> = HashMap::new();
    for body in m.function_bodies() {
        let b = body.body.slice(data);
        let Some(start) = opc::skip_locals(b) else {
            continue;
        };
        let mut iter = InstrIter::new(b, start);
        while let Some((p, _)) = iter.next() {
            if b[p] == 0x10 {
                if let Some((c, _)) = leb128::read_u32(&b[p + 1..]) {
                    *counts.entry(c).or_insert(0) += 1;
                }
            }
        }
    }
    counts
}

#[test]
#[ignore]
fn inline_opportunity() {
    let Ok(bytes) = std::fs::read("/tmp/real.wasm") else {
        return;
    };
    let wilt_out = wilt::optimise(&bytes);
    let counts = count_callsites(&wilt_out);

    let mut bucket = [0u32; 6]; // 0,1,2,3,4,>=5
    for &c in counts.values() {
        let i = if c >= 5 { 5 } else { c as usize };
        bucket[i] += 1;
    }
    println!("\n── call-count distribution in wilt output ──");
    for (i, n) in bucket.iter().enumerate() {
        let label = if i == 5 {
            ">=5".to_string()
        } else {
            i.to_string()
        };
        println!("  called {label:>3} times: {n} functions");
    }
}

#[test]
#[ignore]
fn dupe_detect() {
    let path = "/tmp/real.wasm";
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    let wilt_out = wilt::optimise(&bytes);
    let Some(opt_out) = wasm_opt(path) else {
        return;
    };

    let (n_in, raw_in, canon_in) = dupe_stats(&bytes);
    let (n_w, raw_w, canon_w) = dupe_stats(&wilt_out);
    let (n_o, raw_o, canon_o) = dupe_stats(&opt_out);

    println!("\n── function-body dupe detection on {path} ──");
    println!(
        "{:<14} {:>7} {:>12} {:>18}",
        "source", "funcs", "byte-dupes", "canon-dupes"
    );
    println!(
        "{:<14} {:>7} {:>12} {:>18}",
        "input", n_in, raw_in, canon_in
    );
    println!("{:<14} {:>7} {:>12} {:>18}", "wilt", n_w, raw_w, canon_w);
    println!(
        "{:<14} {:>7} {:>12} {:>18}",
        "wasm-opt", n_o, raw_o, canon_o
    );
    println!();
    println!("byte-dupes:  extra copies of byte-identical bodies");
    println!("canon-dupes: extra copies after mapping local indices to first-use order");
    println!("If canon-dupes ≫ byte-dupes in wilt's output, canonicalisation");
    println!("would let dedup catch the extras.");
}
