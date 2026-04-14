//! `wilt` — WebAssembly In Link Time — CLI optimiser.
//!
//! Drop-in for most `wasm-opt` invocations. Accepts the common flags
//! (`-O`, `-O1..-O3`, `-Os`, `-Oz`, `-o`, `--strip-debug`,
//! `--strip-producers`, `--enable-*`, `-g`, `--print`, `-v`) and
//! translates them onto wilt's pipeline. Unknown flags with an
//! `--enable-` / `--disable-` / `--pass-` prefix are silently
//! accepted so `wasm-opt`-shaped invocations don't need rewriting.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
wilt — WebAssembly optimiser (drop-in for most `wasm-opt` usage)

USAGE:
    wilt <INPUT> [-o <OUTPUT>] [OPTIONS...]

OPTIONS:
    -o, --output <P>        Output path (required unless --print)
    -O, -O1, -O2, -O3       Optimisation level. All map to wilt's
    -Os, -Oz                pipeline (wilt has one mode; these are
                            accepted for drop-in compatibility).
    -g, --debuginfo         Preserve debug-info custom sections.
                            This is wilt's default — noted for clarity.
    --strip-debug           Strip DWARF + source-map custom sections.
    --strip-producers       Strip `producers` custom section.
    --strip                 Strip DWARF, source maps, names, target_features
                            (matches `wasm-opt -O --strip-debug`'s output).
    --source-map-in <PATH>  External V3 source map for the input.
                            Without this, if the input carries a
                            `sourceMappingURL` we strip it and warn
                            (since any map describes the pre-opt code).
    --source-map-out <PATH> Where to write the rewritten map.
                            The output wasm's sourceMappingURL is
                            updated to reference this path.
    --debug=<level>         Set debug-info fidelity tier:
                              none  — strip everything
                              names — rewrite `name` section to match
                                      output (default when implemented)
                              lines — names + DWARF `.debug_line` (future)
                              full  — everything rewritten (future)
                            -g0/-g1/-g2/-g3 are aliases.
    --enable-<feature>      Accepted for compatibility; wilt supports
    --disable-<feature>     MVP + SIMD + multi-value + bulk-memory +
                            reference-types + non-trapping-float natively.
    --print                 Write output to stdout.
    -v, --verbose           Report input/output sizes.
    -h, --help              Show this help.

Unknown `--pass-*`, `--enable-*`, `--disable-*` flags are accepted
silently. Unknown other flags produce an error.

EXIT CODES:
    0 — success
    1 — IO / parse error
    2 — invalid arguments
";

#[derive(Default)]
struct Args {
    input: Option<PathBuf>,
    output: Option<PathBuf>,
    print_stdout: bool,
    strip_all: bool,
    strip_debug: bool,
    strip_producers: bool,
    keep_debuginfo: bool,
    verbose: bool,
    /// Explicit `--debug=<level>`. `None` = not set, use default
    /// (which today yields `optimise()` style output without names-
    /// tier rewriting — future work upgrades the default).
    debug_level: Option<wilt::debug_level::DebugLevel>,
    /// `--source-map-in <path>`: external V3 source map describing
    /// the input. When the output would otherwise reference a stale
    /// map, supplying this + `source_map_out` lets wilt transform
    /// it to stay consistent with the optimised output.
    source_map_in: Option<PathBuf>,
    /// `--source-map-out <path>`: where wilt writes the rewritten map.
    source_map_out: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args::default();
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        let arg = &raw[i];
        match arg.as_str() {
            "-h" | "--help" => { print!("{USAGE}"); std::process::exit(0); }
            "-v" | "--verbose" => { a.verbose = true; i += 1; }
            // Optimisation levels — all equivalent for wilt.
            "-O" | "-O0" | "-O1" | "-O2" | "-O3" | "-O4" | "-Os" | "-Oz" => { i += 1; }
            // Debug-level flag: --debug=none/names/lines/full.
            s if s.starts_with("--debug=") => {
                let v = &s[8..];
                a.debug_level = Some(wilt::debug_level::DebugLevel::parse(v)
                    .ok_or_else(|| format!("--debug: unknown level {v:?} (want none/names/lines/full)"))?);
                i += 1;
            }
            "--debug" => {
                i += 1;
                let v = raw.get(i).ok_or_else(|| "--debug: expected level".to_string())?;
                a.debug_level = Some(wilt::debug_level::DebugLevel::parse(v)
                    .ok_or_else(|| format!("--debug: unknown level {v:?}"))?);
                i += 1;
            }
            "--source-map-in" => {
                i += 1;
                let v = raw.get(i).ok_or_else(|| "--source-map-in: expected path".to_string())?;
                a.source_map_in = Some(PathBuf::from(v));
                i += 1;
            }
            s if s.starts_with("--source-map-in=") => {
                a.source_map_in = Some(PathBuf::from(&s["--source-map-in=".len()..]));
                i += 1;
            }
            "--source-map-out" => {
                i += 1;
                let v = raw.get(i).ok_or_else(|| "--source-map-out: expected path".to_string())?;
                a.source_map_out = Some(PathBuf::from(v));
                i += 1;
            }
            s if s.starts_with("--source-map-out=") => {
                a.source_map_out = Some(PathBuf::from(&s["--source-map-out=".len()..]));
                i += 1;
            }
            "-g0" => { a.debug_level = Some(wilt::debug_level::DebugLevel::None);  i += 1; }
            "-g1" => { a.debug_level = Some(wilt::debug_level::DebugLevel::Names); i += 1; }
            "-g2" => { a.debug_level = Some(wilt::debug_level::DebugLevel::Lines); i += 1; }
            "-g3" => { a.debug_level = Some(wilt::debug_level::DebugLevel::Full);  i += 1; }
            // Debug / strip flags.
            "-g" | "--debuginfo" => { a.keep_debuginfo = true; i += 1; }
            "--strip" => { a.strip_all = true; i += 1; }
            "--strip-debug" | "--strip-dwarf" => { a.strip_debug = true; i += 1; }
            "--strip-producers" => { a.strip_producers = true; i += 1; }
            "--strip-target-features" => { i += 1; /* folded into --strip */ }
            "--print" => { a.print_stdout = true; i += 1; }
            // Output.
            "-o" | "--output" => {
                i += 1;
                let v = raw.get(i).ok_or_else(|| format!("{arg}: expected path"))?;
                a.output = Some(PathBuf::from(v));
                i += 1;
            }
            s if s.starts_with("-o=") => {
                a.output = Some(PathBuf::from(&s[3..])); i += 1;
            }
            s if s.starts_with("--output=") => {
                a.output = Some(PathBuf::from(&s[9..])); i += 1;
            }
            // wasm-opt feature toggles + pass flags — accept and ignore.
            s if s.starts_with("--enable-")
              || s.starts_with("--disable-")
              || s.starts_with("--pass-")
              || s.starts_with("--no-") => { i += 1; }
            // Some wasm-opt flags take an arg; accept and skip it for known ones.
            "--features" | "--mvp-features" | "--all-features" => {
                // --features takes a value; others stand alone. Peek:
                if arg == "--features" { i += 2; } else { i += 1; }
            }
            s if s.starts_with("-") => return Err(format!("unknown flag: {s}")),
            _ => {
                if a.input.is_some() {
                    return Err(format!("unexpected positional arg: {arg}"));
                }
                a.input = Some(PathBuf::from(arg));
                i += 1;
            }
        }
    }
    Ok(a)
}

fn default_output_path(input: &std::path::Path) -> PathBuf {
    let stem = input.file_stem().and_then(|s| s.to_str()).unwrap_or("out");
    let dir = input.parent().unwrap_or(std::path::Path::new("."));
    dir.join(format!("{stem}.opt.wasm"))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("wilt: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let Some(input_path) = args.input.as_deref() else {
        eprintln!("wilt: missing <INPUT> argument\n\n{USAGE}");
        return ExitCode::from(2);
    };

    let input_bytes = match std::fs::read(input_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("wilt: could not read {}: {e}", input_path.display());
            return ExitCode::from(1);
        }
    };

    // Strip policy — later flags don't override earlier; we take the
    // union. --strip (our full shipping strip) wins if set. --debuginfo
    // vetoes --strip-debug (matches wasm-opt's -g behaviour).
    let shipping_strip = args.strip_all;
    let partial_strip = !shipping_strip
        && (args.strip_debug || args.strip_producers)
        && !args.keep_debuginfo;

    let mut output_bytes = if let Some(level) = args.debug_level {
        wilt::optimise_with_debug_level(&input_bytes, level)
    } else if shipping_strip {
        wilt::optimise_stripped(&input_bytes)
    } else {
        wilt::optimise(&input_bytes)
    };

    // Handle external source-map reference. If input carries one:
    // - When --source-map-in/out supplied: rewrite through (step 2 —
    //   today the rewrite is pipe-through when code is unchanged;
    //   otherwise we strip with warning).
    // - When neither supplied: strip the reference from output and
    //   warn.
    if let Ok(input_m) = wilt::WasmModule::parse(&input_bytes) {
        if let Some(in_url) = wilt::passes::source_map::detect_url(&input_m) {
            match (args.source_map_in.as_deref(), args.source_map_out.as_deref()) {
                (Some(in_path), Some(out_path)) => {
                    let in_json = match std::fs::read_to_string(in_path) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("wilt: could not read {}: {e}", in_path.display());
                            return ExitCode::from(1);
                        }
                    };
                    // Use the full-pipeline entry point: it threads
                    // the real FuncRemap + per-function offsets into
                    // the VLQ rewriter.
                    let (new_bytes, maybe_new_map) =
                        wilt::optimise_with_source_map(&input_bytes, Some(&in_json));
                    output_bytes = new_bytes;
                    match maybe_new_map {
                        Some(new_json) => {
                            if let Err(e) = std::fs::write(out_path, new_json) {
                                eprintln!("wilt: could not write {}: {e}", out_path.display());
                                return ExitCode::from(1);
                            }
                            let out_url = out_path.file_name()
                                .and_then(|s| s.to_str())
                                .unwrap_or(&in_url);
                            output_bytes = wilt::passes::source_map::set_url(&output_bytes, out_url);
                            if args.verbose {
                                let _ = writeln!(
                                    std::io::stderr(),
                                    "wilt: rewrote source map → {}", out_path.display(),
                                );
                            }
                        }
                        None => {
                            output_bytes = wilt::passes::source_map::strip_url(&output_bytes);
                            let _ = writeln!(
                                std::io::stderr(),
                                "wilt: source map {in_url:?} stripped — bodies modified beyond \
                                 what the source-map rewriter handles today",
                            );
                        }
                    }
                }
                _ => {
                    // User didn't supply paths → strip + warn.
                    output_bytes = wilt::passes::source_map::strip_url(&output_bytes);
                    let _ = writeln!(
                        std::io::stderr(),
                        "wilt: input references external source map {in_url:?} — dropping \
                         reference from output. Pass --source-map-in <path> --source-map-out \
                         <path> to maintain consistency.",
                    );
                }
            }
        }
    }

    if partial_strip {
        if let Ok(m) = wilt::WasmModule::parse(&output_bytes) {
            use wilt::passes::strip::StripConfig;
            let cfg = StripConfig {
                dwarf: args.strip_debug,
                source_maps: args.strip_debug,
                producers: args.strip_producers,
                ..StripConfig::default()
            };
            let stripped = wilt::passes::strip::apply(&m, cfg);
            if stripped.len() < output_bytes.len() {
                output_bytes = stripped;
            }
        }
    }

    if args.print_stdout {
        let mut stdout = std::io::stdout();
        if let Err(e) = stdout.write_all(&output_bytes) {
            eprintln!("wilt: write stdout: {e}");
            return ExitCode::from(1);
        }
    } else {
        let out_path = args.output
            .unwrap_or_else(|| default_output_path(input_path));
        if let Err(e) = std::fs::write(&out_path, &output_bytes) {
            eprintln!("wilt: could not write {}: {e}", out_path.display());
            return ExitCode::from(1);
        }
        if args.verbose {
            let inp = input_bytes.len();
            let out = output_bytes.len();
            let saved = inp.saturating_sub(out);
            let pct = if inp > 0 { 100.0 * saved as f64 / inp as f64 } else { 0.0 };
            let _ = writeln!(
                std::io::stderr(),
                "wilt: {} → {}  ({inp} → {out} bytes, saved {saved}, {pct:.1}%)",
                input_path.display(), out_path.display(),
            );
        }
    }

    ExitCode::SUCCESS
}
