//! Debugger-roundtrip test harness for DWARF rewrite work.
//!
//! Wraps the `addr2line` crate (which builds on `gimli`) to verify
//! that the DWARF in a linked binary actually decodes correctly:
//! take a list of function entry points from the symbol table, ask
//! the resolver to map each to (function, file, line), and report
//! any that come back empty or garbage.
//!
//! Modes:
//!
//!   * `verify <path/to/elf>` — single-binary smoke test. Reports
//!     resolver success rate over a sample of symbols.
//!
//!   * `compare <before.elf> <after.elf>` — link-then-link
//!     regression test. Resolves the same symbol names in both
//!     binaries (matched by name; addresses may have shifted) and
//!     asserts the resolved (file, line, function) tuples match.
//!     Used to gate any DWARF rewrite against silent corruption.
//!
//! Pure Rust — no external `llvm-symbolizer` / `addr2line` binary
//! needed. Works on ELF + Mach-O (anything `object` parses). Does
//! not handle SHF_COMPRESSED inputs (we run the harness against
//! uncompressed builds; compression is a separate, downstream
//! concern). Mach-O dSYM bundles aren't followed; the test fixture
//! must keep DWARF in the binary itself.
//!
//! Exit codes:
//!   * 0  — verify passed / compare matched.
//!   * 1  — usage error / file open error.
//!   * 2  — DWARF resolution regression detected.

use object::Object;
use object::ObjectSection;
use object::ObjectSymbol;
use std::env;
use std::path::Path;
use std::process::ExitCode;
use std::rc::Rc;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Resolution {
    /// The demangled function name as gimli resolved it (may differ
    /// from the symbol-table name when the DIE-level name is
    /// non-mangled, e.g. for inlined frames).
    function: Option<String>,
    /// Source file path as recorded in DWARF, or None if unknown.
    file: Option<String>,
    /// Source line, or None if unknown.
    line: Option<u32>,
}

fn open_object(path: &Path) -> Result<(Vec<u8>, &'static [u8]), String> {
    // Leak the bytes so the borrow lives 'static for the addr2line
    // context. Standalone tool — process exits soon, ok.
    let bytes = std::fs::read(path).map_err(|e| format!("read {path:?}: {e}"))?;
    let leaked: &'static [u8] = Box::leak(bytes.clone().into_boxed_slice());
    Ok((bytes, leaked))
}

fn resolve_addr(
    ctx: &addr2line::Context<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
    addr: u64,
) -> Result<Resolution, String> {
    let mut frames = ctx
        .find_frames(addr)
        .skip_all_loads()
        .map_err(|e| format!("find_frames @ 0x{addr:x}: {e}"))?;
    if let Some(frame) = frames.next().map_err(|e| format!("frame iter: {e}"))? {
        let function = frame
            .function
            .as_ref()
            .and_then(|f| f.demangle().ok().map(|s| s.into_owned()));
        let (file, line) = match frame.location {
            Some(loc) => (loc.file.map(|s| s.to_owned()), loc.line),
            None => (None, None),
        };
        Ok(Resolution { function, file, line })
    } else {
        Ok(Resolution {
            function: None,
            file: None,
            line: None,
        })
    }
}

type Reader = gimli::EndianRcSlice<gimli::RunTimeEndian>;

fn build_context(bytes: &'static [u8]) -> Result<addr2line::Context<Reader>, String> {
    let obj = object::File::parse(bytes).map_err(|e| format!("parse: {e}"))?;
    let endian = if obj.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let load = |id: gimli::SectionId| -> Result<Reader, gimli::Error> {
        let data = obj
            .section_by_name(id.name())
            .and_then(|s| s.uncompressed_data().ok())
            .unwrap_or(std::borrow::Cow::Borrowed(&[]));
        let owned: Rc<[u8]> = Rc::from(data.as_ref());
        Ok(gimli::EndianRcSlice::new(owned, endian))
    };
    let dwarf = gimli::Dwarf::load(load).map_err(|e| format!("dwarf load: {e}"))?;
    addr2line::Context::from_dwarf(dwarf).map_err(|e| format!("addr2line ctx: {e}"))
}

/// Pick up to `n` distinct, **uniquely-named** function symbols from
/// `bytes`. Returns `(name, address)` pairs in symbol-table order.
/// Skips:
///   * non-text symbols
///   * empty names
///   * zero-address symbols (PLT stubs etc)
///   * any name that appears more than once in the symbol table
///     (COMDAT folding produces same-name aliases at different
///     addresses; an address-by-name lookup would be ambiguous and
///     the compare-mode regression check would false-positive)
fn pick_function_addresses(bytes: &[u8], n: usize) -> Result<Vec<(String, u64)>, String> {
    let obj = object::File::parse(bytes).map_err(|e| format!("parse: {e}"))?;
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut order: Vec<(String, u64)> = Vec::new();
    for sym in obj.symbols() {
        if sym.kind() != object::SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let addr = sym.address();
        if addr == 0 {
            continue;
        }
        *counts.entry(name.to_owned()).or_insert(0) += 1;
        order.push((name.to_owned(), addr));
    }
    let mut picks = Vec::new();
    for (name, addr) in order {
        if counts.get(&name).copied().unwrap_or(0) == 1 {
            picks.push((name, addr));
            if picks.len() >= n {
                break;
            }
        }
    }
    Ok(picks)
}

fn verify(path: &Path) -> Result<(), String> {
    let (_owned, leaked) = open_object(path)?;
    let ctx = build_context(leaked)?;
    let picks = pick_function_addresses(leaked, 64)?;
    if picks.is_empty() {
        return Err(format!("no function symbols in {path:?}"));
    }

    let mut ok = 0usize;
    let mut nofile = 0usize;
    for (name, addr) in &picks {
        let r = resolve_addr(&ctx, *addr)?;
        if r.function.is_some() && r.file.is_some() && r.line.is_some() {
            ok += 1;
        } else if r.function.is_some() {
            // We got a function name but no file/line — common for
            // things like crt entry points or stripped CUs. Still
            // counts as "DWARF works."
            nofile += 1;
        } else {
            eprintln!("  unresolved: {name} @ 0x{addr:x}");
        }
    }
    println!(
        "verify({}): {} resolved with file/line, {} resolved name-only, {}/{} symbols",
        path.display(),
        ok,
        nofile,
        ok + nofile,
        picks.len()
    );
    if ok + nofile == 0 {
        return Err("DWARF resolved nothing — broken".into());
    }
    Ok(())
}

fn compare(before: &Path, after: &Path) -> Result<(), String> {
    let (_b_owned, b_leaked) = open_object(before)?;
    let (_a_owned, a_leaked) = open_object(after)?;
    let b_ctx = build_context(b_leaked)?;
    let a_ctx = build_context(a_leaked)?;

    // Same uniqueness filter on the after-binary so a name that
    // appears once in `before` but multiple times in `after` (e.g.
    // because the rewrite pass duplicated something) doesn't quietly
    // map to the wrong address.
    let b_picks = pick_function_addresses(b_leaked, 256)?;
    let a_picks = pick_function_addresses(a_leaked, usize::MAX)?;
    let a_addr: std::collections::HashMap<String, u64> = a_picks.into_iter().collect();

    let mut compared = 0usize;
    let mut mismatches: Vec<String> = Vec::new();
    for (name, b_addr_val) in &b_picks {
        let Some(&a_addr_val) = a_addr.get(name) else {
            continue;
        };
        if a_addr_val == 0 {
            continue;
        }
        let b = resolve_addr(&b_ctx, *b_addr_val)?;
        let a = resolve_addr(&a_ctx, a_addr_val)?;
        compared += 1;
        if b != a {
            mismatches.push(format!("{name}: before={b:?} after={a:?}"));
        }
    }
    println!(
        "compare: {} symbol pairs, {} mismatches",
        compared,
        mismatches.len()
    );
    for m in mismatches.iter().take(10) {
        println!("  MISMATCH {m}");
    }
    if !mismatches.is_empty() {
        return Err(format!("{} regressions", mismatches.len()));
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let result = match args.get(1).map(|s| s.as_str()) {
        Some("verify") if args.len() == 3 => verify(Path::new(&args[2])),
        Some("compare") if args.len() == 4 => compare(Path::new(&args[2]), Path::new(&args[3])),
        _ => {
            eprintln!(
                "usage:\n  {0} verify <elf>\n  {0} compare <before.elf> <after.elf>",
                args[0]
            );
            return ExitCode::from(1);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
