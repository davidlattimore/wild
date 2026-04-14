// WASM argument parsing for the wasm-ld-compatible linker interface.
//
// Reference: https://lld.llvm.org/WebAssembly.html
// Reference: https://github.com/WebAssembly/tool-conventions/blob/main/Linking.md
#![allow(unused_variables)]

use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::args::RelocationModel;
use crate::args::Strip;
use crate::error::Result;
use crate::platform;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct WasmArgs {
    pub(crate) common: super::CommonArgs,
    pub(crate) output: Arc<Path>,
    pub(crate) entry_symbol: Option<Vec<u8>>,
    pub(crate) lib_search_paths: Vec<Box<Path>>,
    pub(crate) no_entry: bool,
    pub(crate) allow_undefined: bool,
    pub(crate) export_dynamic: bool,
    /// Explicitly set to false by --no-export-dynamic.
    pub(crate) no_export_dynamic: bool,
    pub(crate) no_gc_sections: bool,
    /// Symbols to explicitly export (--export=<sym>).
    pub(crate) exports: Vec<String>,
    /// Symbols to export if defined (--export-if-defined=<sym>).
    pub(crate) exports_if_defined: Vec<String>,
    /// Export all non-hidden symbols.
    pub(crate) export_all: bool,
    pub(crate) strip: Strip,
    /// Relocatable output (-r/--relocatable).
    pub(crate) is_relocatable: bool,
    /// Shared library output (-shared).
    pub(crate) is_shared: bool,
    /// Initial memory size in bytes (--initial-memory).
    pub(crate) initial_memory: Option<u64>,
    /// Maximum memory size (--max-memory).
    pub(crate) max_memory: Option<u64>,
    /// Stack size override (-z stack-size=N).
    pub(crate) stack_size: Option<u64>,
    /// Place stack before data (--stack-first).
    /// Place stack before data (--stack-first, default).
    pub(crate) stack_first: bool,
    /// Global data base address (--global-base).
    pub(crate) global_base: Option<u64>,
    /// Initial heap size (--initial-heap).
    pub(crate) initial_heap: Option<u64>,
    /// Allow multiple definitions (--allow-multiple-definition).
    pub(crate) allow_multiple_definitions: bool,
    /// Symbols to force undefined (-u/--undefined).
    pub(crate) force_undefined: Vec<String>,
    /// Shared memory mode (--shared-memory).
    pub(crate) shared_memory: bool,
    /// Import memory from environment (--import-memory).
    pub(crate) import_memory: bool,
    /// Import function table (--import-table).
    pub(crate) import_table: bool,
    /// Export function table (--export-table).
    pub(crate) export_table: bool,
    /// Suppress non-growable memory (--no-growable-memory).
    pub(crate) no_growable_memory: bool,
    /// Allow table to grow (--growable-table).
    pub(crate) growable_table: bool,
    /// Compress LEB128 in code section (--compress-relocations).
    pub(crate) compress_relocations: bool,
    /// Target is memory64 / wasm64 (`--features=+memory64`, `-mwasm64`,
    /// `--target=wasm64-…`). When true, memory/data/imports carry the
    /// 0x04 limits bit and active data segments use `i64.const` offsets.
    pub(crate) memory64: bool,
    /// Position-independent code / executable. Distinct from `is_shared`:
    /// a shared library implies PIC, but a PIE executable does too. Set
    /// by `-pie`, `--pie`, or `--experimental-pic`.
    pub(crate) is_pic: bool,
    /// Optimisation level from `-O<N>`. Zero (the default) keeps wild
    /// byte-compatible with wasm-ld. `>= 1` enables the wilt post-link
    /// optimisation pipeline (DCE, type-GC, const-fold, layout).
    pub(crate) opt_level: u8,
}

impl Default for WasmArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            output: Arc::from(Path::new("a.out")),
            entry_symbol: None,
            lib_search_paths: Vec::new(),
            no_entry: false,
            allow_undefined: false,
            export_dynamic: false,
            no_export_dynamic: false,
            no_gc_sections: false,
            exports: Vec::new(),
            exports_if_defined: Vec::new(),
            export_all: false,
            strip: Strip::Nothing,
            is_relocatable: false,
            is_shared: false,
            initial_memory: None,
            max_memory: None,
            stack_size: None,
            stack_first: true, // wasm-ld default
            global_base: None,
            initial_heap: None,
            allow_multiple_definitions: false,
            force_undefined: Vec::new(),
            shared_memory: false,
            import_memory: false,
            import_table: false,
            export_table: false,
            no_growable_memory: false,
            growable_table: false,
            compress_relocations: false,
            memory64: false,
            is_pic: false,
            opt_level: 0,
        }
    }
}

impl WasmArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }
}

impl platform::Args for WasmArgs {
    fn parse<S, I>(&mut self, input: I) -> Result
    where
        S: AsRef<str>,
        I: Iterator<Item = S>,
    {
        parse(self, input)
    }

    fn should_strip_debug(&self) -> bool {
        matches!(self.strip, Strip::All | Strip::Debug)
    }

    fn should_strip_all(&self) -> bool {
        matches!(self.strip, Strip::All)
    }

    fn entry_symbol_name<'a>(&'a self, linker_script_entry: Option<&'a [u8]>) -> &'a [u8] {
        if self.no_entry {
            return b"";
        }
        linker_script_entry
            .or(self.entry_symbol.as_deref())
            .unwrap_or(b"_start")
    }

    fn has_explicit_entry(&self) -> bool {
        self.entry_symbol.is_some()
    }

    fn lib_search_path(&self) -> &[Box<Path>] {
        &self.lib_search_paths
    }

    fn output(&self) -> &Arc<Path> {
        &self.output
    }

    fn common(&self) -> &CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut CommonArgs {
        &mut self.common
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        if self.no_export_dynamic {
            return false;
        }
        self.export_dynamic || self.export_all || self.is_shared
    }

    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        false
    }

    fn should_gc_sections(&self) -> bool {
        !self.no_gc_sections
    }

    fn wasm_opt_level(&self) -> u8 {
        self.opt_level
    }

    fn should_allow_object_undefined(
        &self,
        _output_kind: crate::OutputKind,
    ) -> bool {
        self.allow_undefined
    }

    fn allow_multiple_definitions(&self) -> bool {
        self.allow_multiple_definitions
    }

    fn force_undefined_symbol_names(&self) -> &[String] {
        &self.force_undefined
    }

    fn force_export_symbol_names(&self) -> &[String] {
        &self.exports
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        // WASM has no segments — per spec, memory is a single linear block.
        crate::alignment::Alignment { exponent: 0 }
    }

    fn should_merge_sections(&self) -> bool {
        false
    }

    fn relocation_model(&self) -> RelocationModel {
        RelocationModel::NonRelocatable
    }

    fn should_output_executable(&self) -> bool {
        !self.is_shared && !self.is_relocatable
    }

    fn should_output_partial_object(&self) -> bool {
        self.is_relocatable
    }
}

#[allow(clippy::unnecessary_wraps)]
fn parse<S: AsRef<str>, I: Iterator<Item = S>>(args: &mut WasmArgs, input: I) -> Result {
    let mut inputs = Vec::new();
    let mut modifiers = Modifiers::default();

    let mut iter = input.peekable();
    while let Some(arg) = iter.next() {
        let arg = arg.as_ref();
        match arg {
            // --- Output ---
            "-o" => {
                if let Some(path) = iter.next() {
                    args.output = Arc::from(Path::new(path.as_ref()));
                }
            }
            _ if arg.starts_with("-o") => {
                args.output = Arc::from(Path::new(&arg[2..]));
            }

            // --- Entry point (spec §9.2: linker resolves entry symbol) ---
            "-e" | "--entry" => {
                if let Some(sym) = iter.next() {
                    args.entry_symbol = Some(sym.as_ref().as_bytes().to_vec());
                }
            }
            _ if arg.starts_with("--entry=") => {
                args.entry_symbol = Some(arg.as_bytes()[8..].to_vec());
            }
            "--no-entry" => args.no_entry = true,

            // --- Symbol resolution (spec §9.2) ---
            "--allow-undefined" | "-allow-undefined" => args.allow_undefined = true,
            "--allow-multiple-definition" => args.allow_multiple_definitions = true,
            "--no-allow-multiple-definition" => args.allow_multiple_definitions = false,

            // --- Exports (spec §9.2: export for each defined symbol with
            //     non-local linkage and non-hidden visibility) ---
            "--export-dynamic" => args.export_dynamic = true,
            "--no-export-dynamic" => {
                args.export_dynamic = false;
                args.no_export_dynamic = true;
            }
            "--export-all" => args.export_all = true,
            _ if arg.starts_with("--export=") => {
                args.exports.push(arg[9..].to_string());
            }
            "--export" => {
                if let Some(sym) = iter.next() {
                    args.exports.push(sym.as_ref().to_string());
                }
            }
            _ if arg.starts_with("--export-if-defined=") => {
                args.exports_if_defined.push(arg[20..].to_string());
            }
            "--export-table" => args.export_table = true,
            "--import-table" => args.import_table = true,

            // --- Memory layout (spec §9.1: data segment merging) ---
            _ if arg.starts_with("--initial-memory=") => {
                args.initial_memory = arg[17..].parse().ok();
            }
            _ if arg.starts_with("--max-memory=") => {
                args.max_memory = arg[13..].parse().ok();
            }
            _ if arg.starts_with("--global-base=") => {
                args.global_base = arg[14..].parse().ok();
            }
            _ if arg.starts_with("--initial-heap=") => {
                args.initial_heap = arg[15..].parse().ok();
            }
            "--stack-first" => args.stack_first = true,
            "--no-stack-first" => args.stack_first = false,
            "--no-growable-memory" => args.no_growable_memory = true,
            "--growable-table" => args.growable_table = true,
            "--import-memory" => args.import_memory = true,
            "--shared-memory" => args.shared_memory = true,

            // --- -z flags ---
            "-z" => {
                if let Some(val) = iter.next() {
                    let val = val.as_ref();
                    if let Some(size) = val.strip_prefix("stack-size=") {
                        args.stack_size = size.parse().ok();
                    }
                    // Other -z flags silently accepted
                }
            }

            // --- GC ---
            "--gc-sections" => args.no_gc_sections = false,
            "--no-gc-sections" | "-no-gc-sections" => args.no_gc_sections = true,

            // --- Strip ---
            "--strip-debug" | "-S" => args.strip = Strip::Debug,
            "--strip-all" | "-s" => args.strip = Strip::All,

            // --- Relocatable / shared ---
            "-r" | "--relocatable" => args.is_relocatable = true,
            "-shared" | "--shared" => args.is_shared = true,

            // --- Undefined symbols ---
            "-u" | "--undefined" => {
                if let Some(sym) = iter.next() {
                    args.force_undefined.push(sym.as_ref().to_string());
                }
            }
            _ if arg.starts_with("--undefined=") => {
                args.force_undefined.push(arg[12..].to_string());
            }

            // --- Library search ---
            "-L" => {
                if let Some(path) = iter.next() {
                    args.lib_search_paths
                        .push(Box::from(Path::new(path.as_ref())));
                }
            }
            _ if arg.starts_with("-L") => {
                args.lib_search_paths
                    .push(Box::from(Path::new(&arg[2..])));
            }
            "-l" => {
                if let Some(name) = iter.next() {
                    inputs.push(Input {
                        spec: InputSpec::Lib(name.as_ref().into()),
                        search_first: None,
                        modifiers,
                    });
                }
            }
            _ if arg.starts_with("-l") => {
                inputs.push(Input {
                    spec: InputSpec::Lib(arg[2..].into()),
                    search_first: None,
                    modifiers,
                });
            }

            // --- Archive modifiers ---
            "--whole-archive" => modifiers.whole_archive = true,
            "--no-whole-archive" => modifiers.whole_archive = false,
            "--start-lib" => modifiers.archive_semantics = true,
            "--end-lib" => modifiers.archive_semantics = false,

            // --- Target/arch ---
            "--target" => {
                if let Some(t) = iter.next() {
                    if t.as_ref().starts_with("wasm64") {
                        args.memory64 = true;
                    }
                }
            }
            _ if arg.starts_with("--target=") => {
                if arg["--target=".len()..].starts_with("wasm64") {
                    args.memory64 = true;
                }
            }
            "-m" => {
                if let Some(t) = iter.next()
                    && t.as_ref() == "wasm64"
                {
                    args.memory64 = true;
                }
            }
            "-mwasm64" => args.memory64 = true,
            _ if arg.starts_with("-m") => {} // e.g. other -m variants

            // --- PIC ---
            "--experimental-pic" | "-pie" | "--pie" => args.is_pic = true,
            _ if arg.starts_with("--unresolved-symbols=") => {}
            "--fatal-warnings" => {}
            "--no-fatal-warnings" => {}
            _ if arg.starts_with("--features=") => {
                for feat in arg["--features=".len()..].split(',') {
                    if feat == "+memory64" {
                        args.memory64 = true;
                    }
                }
            }
            _ if arg.starts_with("--extra-features=") => {
                for feat in arg["--extra-features=".len()..].split(',') {
                    if feat == "+memory64" {
                        args.memory64 = true;
                    }
                }
            }
            "--no-check-features" => {}
            "-t" | "--trace" => {}
            _ if arg.starts_with("-y") => {} // trace symbol
            _ if arg.starts_with("--trace-symbol=") => {}
            _ if arg.starts_with("--wrap=") => {}
            "-wrap" | "--wrap" => { iter.next(); }
            _ if arg.starts_with("-rpath") => { if arg == "-rpath" { iter.next(); } }
            _ if arg.starts_with("--rpath=") => {}
            _ if arg.starts_with("--rpath") => { if arg == "--rpath" { iter.next(); } }
            "--print-gc-sections" => {}
            "--no-print-gc-sections" => {}
            "--compress-relocations" => args.compress_relocations = true,
            _ if arg.starts_with("--compress-relocations") => args.compress_relocations = true,
            _ if arg.starts_with("-M") | arg.starts_with("--Map") => {
                if arg == "-M" || arg == "--Map" { iter.next(); }
            }
            "--emit-relocs" => {}
            "--no-merge-data-segments" => {}
            _ if arg.starts_with("--page-size=") => {}
            "--no-shlib-sigcheck" => {}
            _ if arg.starts_with("--build-id") => {}
            "-v" | "--verbose" => {}
            "--version" | "-V" => {}
            "--reproduce" => { iter.next(); }
            _ if arg.starts_with("--reproduce=") => {}
            "--color-diagnostics" | "--no-color-diagnostics" => {}
            _ if arg.starts_with("-O") => {
                // `-O<N>` — optimisation level. `-O` alone is treated as `-O1`.
                let rest = &arg[2..];
                args.opt_level = if rest.is_empty() { 1 } else {
                    rest.parse::<u8>().unwrap_or(1)
                };
            }
            _ if arg.starts_with("--threads=") => {}
            _ if arg.starts_with("--lto") => {}
            _ if arg.starts_with("--thinlto") => {}
            _ if arg.starts_with("--no-lto") => {}
            _ if arg.starts_with("--library-path") => {
                if arg == "--library-path" { iter.next(); }
            }
            _ if arg.starts_with("--library=") => {
                inputs.push(Input {
                    spec: InputSpec::Lib(arg[10..].into()),
                    search_first: None,
                    modifiers,
                });
            }
            "--library" => {
                if let Some(name) = iter.next() {
                    inputs.push(Input {
                        spec: InputSpec::Lib(name.as_ref().into()),
                        search_first: None,
                        modifiers,
                    });
                }
            }

            // --- Response files ---
            _ if arg.starts_with('@') => {
                let path = &arg[1..];
                if let Ok(content) = std::fs::read_to_string(path) {
                    let extra_args: Vec<String> =
                        content.split_whitespace().map(String::from).collect();
                    parse(args, extra_args.into_iter())?;
                }
            }

            // Positional: input file
            _ if !arg.starts_with('-') => {
                inputs.push(Input {
                    spec: InputSpec::File(Box::from(Path::new(arg))),
                    search_first: None,
                    modifiers,
                });
            }

            // Unknown flags: collect but don't error
            _ => {
                args.common.unrecognized_options.push(arg.to_owned());
            }
        }
    }

    args.common.inputs.extend(inputs);
    Ok(())
}
