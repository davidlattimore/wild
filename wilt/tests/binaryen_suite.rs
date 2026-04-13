//! Feature-parity harness against binaryen's test corpus.
//!
//! For every input, wilt must:
//! 1. Not panic.
//! 2. Produce an output that passes the spec validator.
//! 3. Preserve structural invariants (exports / start / module identity).
//! 4. Not grow the module (optimisers don't add bytes).
//!
//! We also track how often wilt actually modifies the input — a high
//! pass-through rate means the scoreboard is flattering us.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn validate(bytes: &[u8]) -> Result<(), String> {
    let mut validator = wasmparser::Validator::new_with_features(wasmparser::WasmFeatures::all());
    validator.validate_all(bytes).map(|_| ()).map_err(|e| e.to_string())
}

fn corpus_root() -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent()?.join("external_test_suites/binaryen/test");
    root.is_dir().then_some(root)
}

fn walk(dir: &Path, exts: &[&str], out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, exts, out);
        } else if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
            if exts.contains(&ext) {
                out.push(p);
            }
        }
    }
}

/// Surface-level facts about a module used for before/after comparison.
/// These must be preserved by *any* correct optimiser pass (except when a
/// pass explicitly removes a function — tracked separately).
#[derive(Debug, PartialEq, Eq)]
struct Shape {
    start: Option<u32>,
    /// Name -> (kind, index). Removing or renaming exports is a breakage.
    exports: BTreeMap<String, (u8, u32)>,
    /// Imports `(module, field, kind)` — we must never drop these.
    imports: Vec<(String, String, u8)>,
    memory_count: u32,
    table_count: u32,
    global_count: u32,
}

/// Derive a Shape from parsed wasm via wasmparser (authoritative decoder).
fn shape(bytes: &[u8]) -> Option<Shape> {
    use wasmparser::{Parser, Payload::*};
    let mut s = Shape {
        start: None,
        exports: BTreeMap::new(),
        imports: Vec::new(),
        memory_count: 0,
        table_count: 0,
        global_count: 0,
    };
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.ok()? {
            StartSection { func, .. } => s.start = Some(func),
            ExportSection(r) => {
                for e in r {
                    let e = e.ok()?;
                    let kind = match e.kind {
                        wasmparser::ExternalKind::Func => 0,
                        wasmparser::ExternalKind::Table => 1,
                        wasmparser::ExternalKind::Memory => 2,
                        wasmparser::ExternalKind::Global => 3,
                        wasmparser::ExternalKind::Tag => 4,
                    };
                    s.exports.insert(e.name.to_string(), (kind, e.index));
                }
            }
            ImportSection(r) => {
                for i in r {
                    let i = i.ok()?;
                    let kind = match i.ty {
                        wasmparser::TypeRef::Func(_) => 0,
                        wasmparser::TypeRef::Table(_) => 1,
                        wasmparser::TypeRef::Memory(_) => 2,
                        wasmparser::TypeRef::Global(_) => 3,
                        wasmparser::TypeRef::Tag(_) => 4,
                    };
                    s.imports.push((i.module.to_string(), i.name.to_string(), kind));
                }
            }
            MemorySection(r) => s.memory_count = r.count(),
            TableSection(r) => s.table_count = r.count(),
            GlobalSection(r) => s.global_count = r.count(),
            _ => {}
        }
    }
    Some(s)
}

#[derive(Default)]
struct Stats {
    total: usize,
    skipped_invalid: usize,
    skipped_unassemblable: usize,
    panicked: Vec<PathBuf>,
    broken_validation: Vec<(PathBuf, String)>,
    shape_changed: Vec<(PathBuf, String)>,
    grew: Vec<(PathBuf, usize, usize)>,
    unchanged: usize,
    modified: usize,
    total_in_bytes: u64,
    total_out_bytes: u64,
}

fn run_case(stats: &mut Stats, rel: &Path, bytes: &[u8]) {
    stats.total += 1;
    if validate(bytes).is_err() {
        stats.skipped_invalid += 1;
        return;
    }
    let before = shape(bytes);

    let out = match std::panic::catch_unwind(|| wilt::optimise(bytes)) {
        Ok(o) => o,
        Err(_) => { stats.panicked.push(rel.to_path_buf()); return; }
    };

    if let Err(e) = validate(&out) {
        stats.broken_validation.push((rel.to_path_buf(), e));
        return;
    }
    if out.len() > bytes.len() {
        stats.grew.push((rel.to_path_buf(), bytes.len(), out.len()));
    }
    stats.total_in_bytes += bytes.len() as u64;
    stats.total_out_bytes += out.len() as u64;
    if out == bytes {
        stats.unchanged += 1;
    } else {
        stats.modified += 1;
    }

    if let (Some(a), Some(b)) = (before, shape(&out)) {
        // Exports must never be dropped or renamed. Indices may shift
        // legitimately (DCE), but the *set of names* must be preserved.
        if a.exports.keys().collect::<Vec<_>>() != b.exports.keys().collect::<Vec<_>>() {
            stats.shape_changed.push((
                rel.to_path_buf(),
                format!("exports differ: {:?} → {:?}",
                        a.exports.keys().collect::<Vec<_>>(),
                        b.exports.keys().collect::<Vec<_>>()),
            ));
            return;
        }
        // Imports may shrink (dup-import-elim is legitimate) but every
        // import in the output must have appeared in the input in the
        // same relative order. Additions or reorderings are regressions.
        let mut ai = a.imports.iter();
        for bi in &b.imports {
            if !ai.any(|x| x == bi) {
                stats.shape_changed.push((rel.to_path_buf(),
                    format!("imports not a subsequence: output contains {bi:?}")));
                return;
            }
        }
        if a.start.is_some() != b.start.is_some() {
            stats.shape_changed.push((rel.to_path_buf(), "start presence changed".into()));
            return;
        }
        for (field, before_count, after_count) in [
            ("memory", a.memory_count, b.memory_count),
            ("table", a.table_count, b.table_count),
            ("global", a.global_count, b.global_count),
        ] {
            if before_count != after_count {
                stats.shape_changed.push((
                    rel.to_path_buf(),
                    format!("{field} count {before_count} → {after_count}"),
                ));
                return;
            }
        }
    }
}

fn report(label: &str, stats: &Stats) {
    let eligible = stats.total - stats.skipped_invalid - stats.skipped_unassemblable;
    let regressions = stats.panicked.len()
        + stats.broken_validation.len()
        + stats.shape_changed.len()
        + stats.grew.len();
    let ok = eligible - regressions;
    let byte_delta = stats.total_in_bytes as i64 - stats.total_out_bytes as i64;
    let modify_rate = if eligible > 0 {
        100.0 * stats.modified as f64 / eligible as f64
    } else { 0.0 };

    eprintln!(
        "\n{label}: {ok}/{eligible} passed \
         ({} invalid inputs, {} unassemblable, \
         {} panicked, {} validation broken, \
         {} shape regressions, {} grew)",
        stats.skipped_invalid, stats.skipped_unassemblable,
        stats.panicked.len(), stats.broken_validation.len(),
        stats.shape_changed.len(), stats.grew.len()
    );
    eprintln!(
        "  pass activity: {} modified ({modify_rate:.1}%), {} unchanged. \
         bytes: {} → {} (saved {byte_delta})",
        stats.modified, stats.unchanged,
        stats.total_in_bytes, stats.total_out_bytes,
    );
    for (p, e) in stats.broken_validation.iter().take(10) {
        eprintln!("  VALIDATION: {} — {}", p.display(), e);
    }
    for (p, e) in stats.shape_changed.iter().take(10) {
        eprintln!("  SHAPE: {} — {}", p.display(), e);
    }
    for (p, a, b) in stats.grew.iter().take(10) {
        eprintln!("  GREW: {} — {} → {} bytes", p.display(), a, b);
    }
    for p in stats.panicked.iter().take(10) {
        eprintln!("  PANIC: {}", p.display());
    }
}

fn fail_on_regression(stats: &Stats) {
    assert!(
        stats.panicked.is_empty()
            && stats.broken_validation.is_empty()
            && stats.shape_changed.is_empty()
            && stats.grew.is_empty(),
        "wilt regressions — see stderr above"
    );
}

#[test]
fn binary_corpus() {
    let Some(root) = corpus_root() else { return };
    let mut files = Vec::new();
    walk(&root, &["wasm"], &mut files);
    files.sort();
    assert!(!files.is_empty());

    let mut stats = Stats::default();
    for p in &files {
        let bytes = std::fs::read(p).unwrap();
        let rel = p.strip_prefix(&root).unwrap();
        run_case(&mut stats, rel, &bytes);
    }
    report("binaryen .wasm corpus", &stats);
    fail_on_regression(&stats);
}

/// Timing baseline for the pipeline. Run with `cargo test --release -p wilt
/// --test binaryen_suite -- --nocapture bench_throughput` to get a meaningful
/// number; debug builds are 5–10× slower than release.
#[test]
fn bench_throughput() {
    let Some(root) = corpus_root() else { return };
    let mut bin = Vec::new();
    walk(&root, &["wasm"], &mut bin);
    bin.sort();
    let mut text = Vec::new();
    walk(&root, &["wat", "wast"], &mut text);
    text.sort();

    // Preload all inputs; we want to measure wilt, not the filesystem.
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for p in &bin {
        inputs.push(std::fs::read(p).unwrap());
    }
    for p in &text {
        if let Ok(Ok(b)) = std::panic::catch_unwind(|| wat::parse_file(p)) {
            inputs.push(b);
        }
    }
    let total_bytes: u64 = inputs.iter().map(|b| b.len() as u64).sum();
    let n = inputs.len();

    let t0 = std::time::Instant::now();
    let mut total_out: u64 = 0;
    for bytes in &inputs {
        let out = wilt::optimise(bytes);
        total_out += out.len() as u64;
    }
    let elapsed = t0.elapsed();

    let mb = total_bytes as f64 / (1024.0 * 1024.0);
    eprintln!(
        "\nbench: {n} modules, {mb:.2} MiB in, {:.2} MiB out, {:.2?} wall, {:.2} MiB/s",
        total_out as f64 / (1024.0 * 1024.0),
        elapsed,
        mb / elapsed.as_secs_f64(),
    );
}

#[test]
fn text_corpus() {
    let Some(root) = corpus_root() else { return };
    let mut files = Vec::new();
    walk(&root, &["wat", "wast"], &mut files);
    files.sort();
    assert!(!files.is_empty());

    let mut stats = Stats::default();
    for p in &files {
        let rel = p.strip_prefix(&root).unwrap();
        let bytes = match std::panic::catch_unwind(|| wat::parse_file(p)) {
            Ok(Ok(b)) => b,
            _ => { stats.total += 1; stats.skipped_unassemblable += 1; continue; }
        };
        run_case(&mut stats, rel, &bytes);
    }
    report("binaryen text corpus", &stats);
    fail_on_regression(&stats);
}
