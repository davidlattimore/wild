// Mach-O argument parsing for the macOS linker driver interface.
#![allow(unused_variables)]

use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::args::RelocationModel;
use crate::args::Strip;
use crate::error::Context as _;
use crate::error::Result;
use crate::platform;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

/// What kind of LC_LOAD_* command to emit for a dylib dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DylibLoadKind {
    Normal,     // LC_LOAD_DYLIB
    Weak,       // LC_LOAD_WEAK_DYLIB
    Reexport,   // LC_REEXPORT_DYLIB
}

#[derive(Debug)]
pub struct MachOArgs {
    pub(crate) common: super::CommonArgs,
    pub(crate) output: Arc<Path>,
    pub(crate) relocation_model: RelocationModel,
    pub(crate) lib_search_paths: Vec<Box<Path>>,
    pub(crate) syslibroot: Option<Box<Path>>,
    pub(crate) entry_symbol: Option<Vec<u8>>,
    pub(crate) explicit_entry: bool,
    pub(crate) strip: Strip,
    pub(crate) strip_locals: bool,
    pub(crate) is_dylib: bool,
    pub(crate) is_relocatable: bool,
    #[allow(dead_code)]
    pub(crate) install_name: Option<Vec<u8>>,
    /// Additional dylibs to emit load commands for (from -l flags resolving to .tbd/.dylib).
    pub(crate) extra_dylibs: Vec<(Vec<u8>, DylibLoadKind)>,
    /// Symbols to force as undefined (-u flag), triggering archive member loading.
    pub(crate) force_undefined: Vec<String>,
    /// Symbols exported by linked dylibs (from .tbd parsing). Used to distinguish
    /// undefined symbols that are dylib imports from truly missing symbols.
    pub(crate) dylib_symbols: std::collections::HashSet<Vec<u8>>,
    /// Whether to skip ad-hoc code signing (-no_adhoc_codesign).
    pub(crate) no_adhoc_codesign: bool,
    /// LC_RPATH entries from -rpath flags.
    pub(crate) rpaths: Vec<Vec<u8>>,
    /// Whether to omit LC_FUNCTION_STARTS (-no_function_starts).
    pub(crate) no_function_starts: bool,
    /// Custom stack size from -stack_size.
    pub(crate) stack_size: Option<u64>,
    /// Whether to omit LC_DATA_IN_CODE (-no_data_in_code_info).
    pub(crate) no_data_in_code: bool,
    /// Minimum OS version for LC_BUILD_VERSION (encoded as Mach-O packed version).
    pub(crate) minos: Option<u32>,
    /// SDK version for LC_BUILD_VERSION (encoded as Mach-O packed version).
    pub(crate) sdk_version: Option<u32>,
    /// The name used for UUID hashing (from -final_output). Falls back to output path.
    pub(crate) final_output: Option<String>,
    /// Whether to omit LC_UUID.
    pub(crate) no_uuid: bool,
    /// Whether to emit a random UUID instead of deterministic.
    pub(crate) random_uuid: bool,
    /// Additional empty sections from -add_empty_section (segname, sectname).
    pub(crate) empty_sections: Vec<([u8; 16], [u8; 16])>,
    /// Whether -export_dynamic was passed.
    pub(crate) export_dynamic: bool,
    /// Whether -dead_strip was passed (GC unreachable sections).
    pub(crate) gc_sections: bool,
    /// Path to exported symbols list file (-exported_symbols_list).
    pub(crate) exported_symbols_list: Option<PathBuf>,
    /// Path to unexported symbols list file (-unexported_symbols_list).
    pub(crate) unexported_symbols_list: Option<PathBuf>,
    /// Inline exported symbols from -exported_symbol flags.
    pub(crate) exported_symbols: Vec<String>,
    /// Inline unexported symbols from -unexported_symbol flags.
    pub(crate) unexported_symbols: Vec<String>,
    /// Dylib compatibility version (packed u32 from -compatibility_version).
    pub(crate) compatibility_version: u32,
    /// Dylib current version (packed u32 from -current_version).
    pub(crate) current_version: u32,
    /// Whether this is a bundle (MH_BUNDLE) output.
    pub(crate) is_bundle: bool,
    /// Sections with embedded file content from -sectcreate (segname, sectname, data).
    pub(crate) sectcreate: Vec<([u8; 16], [u8; 16], Vec<u8>)>,
    /// Framework search paths from -F flags.
    pub(crate) framework_search_paths: Vec<Box<Path>>,
    /// Use extension-first search order (dylibs before static libs across all paths).
    pub(crate) search_dylibs_first: bool,
    /// Frameworks to resolve after all -F paths are collected.
    pending_frameworks: Vec<String>,
    /// .tbd positional inputs to process after -platform_version is known.
    pending_tbd_inputs: Vec<PathBuf>,
}

impl MachOArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }

    /// Add a dylib dependency if not already present (by install name).
    fn add_dylib(&mut self, name: Vec<u8>, kind: DylibLoadKind) {
        if !self.extra_dylibs.iter().any(|(n, _)| n == &name) {
            self.extra_dylibs.push((name, kind));
        }
    }
}

impl Default for MachOArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            relocation_model: RelocationModel::NonRelocatable,
            output: Arc::from(Path::new("a.out")),
            lib_search_paths: Vec::new(),
            syslibroot: None,
            entry_symbol: Some(b"_main".to_vec()),
            explicit_entry: false,
            strip: Strip::Nothing,
            strip_locals: false,
            is_dylib: false,
            is_relocatable: false,
            install_name: None,
            extra_dylibs: Vec::new(),
            force_undefined: Vec::new(),
            dylib_symbols: Default::default(),
            no_adhoc_codesign: false,
            rpaths: Vec::new(),
            no_function_starts: false,
            stack_size: None,
            no_data_in_code: false,
            minos: None,
            sdk_version: None,
            final_output: None,
            no_uuid: false,
            random_uuid: false,
            empty_sections: Vec::new(),
            export_dynamic: false,
            gc_sections: false,
            exported_symbols_list: None,
            unexported_symbols_list: None,
            exported_symbols: Vec::new(),
            unexported_symbols: Vec::new(),
            compatibility_version: 0x01_0000, // 1.0.0
            current_version: 0x01_0000,       // 1.0.0
            is_bundle: false,
            sectcreate: Vec::new(),
            framework_search_paths: Vec::new(),
            search_dylibs_first: false,
            pending_frameworks: Vec::new(),
            pending_tbd_inputs: Vec::new(),
        }
    }
}

impl platform::Args for MachOArgs {
    fn parse<S, I>(&mut self, input: I) -> Result
    where
        S: AsRef<str>,
        I: Iterator<Item = S>,
    {
        parse(self, input)
    }

    fn should_strip_debug(&self) -> bool {
        !self.is_relocatable && matches!(self.strip, Strip::All | Strip::Debug)
    }
    fn should_strip_all(&self) -> bool {
        !self.is_relocatable && matches!(self.strip, Strip::All)
    }

    fn entry_symbol_name<'a>(&'a self, linker_script_entry: Option<&'a [u8]>) -> &'a [u8] {
        linker_script_entry
            .or(self.entry_symbol.as_deref())
            .unwrap_or(b"_main")
    }

    fn has_explicit_entry(&self) -> bool {
        self.explicit_entry
    }

    fn lib_search_path(&self) -> &[Box<std::path::Path>] {
        &self.lib_search_paths
    }

    fn output(&self) -> &std::sync::Arc<std::path::Path> {
        &self.output
    }
    fn common(&self) -> &crate::args::CommonArgs {
        &self.common
    }
    fn common_mut(&mut self) -> &mut crate::args::CommonArgs {
        &mut self.common
    }
    fn should_export_all_dynamic_symbols(&self) -> bool {
        self.export_dynamic
    }
    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        false
    }

    fn should_gc_sections(&self) -> bool {
        self.gc_sections
    }

    fn export_list_path(&self) -> Option<&Path> {
        self.exported_symbols_list.as_deref()
    }

    fn unexport_list_path(&self) -> Option<&Path> {
        self.unexported_symbols_list.as_deref()
    }

    fn dylib_symbols(&self) -> &std::collections::HashSet<Vec<u8>> {
        &self.dylib_symbols
    }

    fn force_undefined_symbol_names(&self) -> &[String] {
        &self.force_undefined
    }

    fn force_export_symbol_names(&self) -> &[String] {
        &self.exported_symbols
    }

    fn force_unexport_symbol_names(&self) -> &[String] {
        &self.unexported_symbols
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        crate::alignment::Alignment { exponent: 14 } // 16KB pages
    }

    fn should_merge_sections(&self) -> bool {
        true
    }

    fn relocation_model(&self) -> crate::args::RelocationModel {
        self.relocation_model
    }

    fn should_output_executable(&self) -> bool {
        !self.is_dylib && !self.is_bundle && !self.is_relocatable
    }

    fn should_output_partial_object(&self) -> bool {
        self.is_relocatable
    }
}

/// Parse macOS linker arguments. Handles the ld64-compatible flags that clang passes.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut MachOArgs,
    mut input: I,
) -> Result {
    let mut modifier_stack = vec![Modifiers::default()];

    while let Some(arg) = input.next() {
        let arg = arg.as_ref();

        // Handle @response files
        if let Some(path) = arg.strip_prefix('@') {
            let file_args = crate::args::read_args_from_file(Path::new(path))?;
            // Re-parse the file contents (simplified - no recursion limit)
            let mut file_iter = file_args.iter().map(|s| s.as_str());
            while let Some(file_arg) = file_iter.next() {
                parse_one_arg(args, file_arg, &mut file_iter, &mut modifier_stack)?;
            }
            continue;
        }

        parse_one_arg(args, arg, &mut input, &mut modifier_stack)?;
    }

    // Resolve deferred .tbd inputs now that -platform_version is known.
    let pending_tbds = std::mem::take(&mut args.pending_tbd_inputs);
    for path in &pending_tbds {
        handle_tbd_input(args, path)?;
    }

    // Resolve deferred framework links now that all -F paths are collected.
    let pending = std::mem::take(&mut args.pending_frameworks);
    for name in &pending {
        link_framework(args, name)?;
    }

    Ok(())
}

fn parse_one_arg<'a, S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut MachOArgs,
    arg: &str,
    input: &mut I,
    modifier_stack: &mut Vec<Modifiers>,
) -> Result {
    // Flags that take a following argument (must be checked before prefix matching)
    match arg {
        "-help" | "--help" => {
            println!("Usage: wild [options] file...");
            println!("  Wild — a fast linker");
            std::process::exit(0);
        }
        "-o" | "--output" => {
            if let Some(val) = input.next() {
                args.output = Arc::from(Path::new(val.as_ref()));
            }
            return Ok(());
        }
        "--time" => {
            args.common.time_phase_options = Some(Vec::new());
            return Ok(());
        }
        "-arch" => {
            input.next();
            return Ok(());
        } // consume and ignore
        "-syslibroot" => {
            if let Some(val) = input.next() {
                args.syslibroot = Some(Box::from(Path::new(val.as_ref())));
            }
            return Ok(());
        }
        "-e" => {
            if let Some(val) = input.next() {
                args.entry_symbol = Some(val.as_ref().as_bytes().to_vec());
                args.explicit_entry = true;
            }
            return Ok(());
        }
        "-u" => {
            if let Some(val) = input.next() {
                args.force_undefined.push(val.as_ref().to_string());
            }
            return Ok(());
        }
        // Flags that take 1 argument, ignored
        "-install_name" => {
            if let Some(val) = input.next() {
                args.install_name = Some(val.as_ref().as_bytes().to_vec());
            }
            return Ok(());
        }
        "-rpath" => {
            if let Some(val) = input.next() {
                args.rpaths.push(val.as_ref().as_bytes().to_vec());
            }
            return Ok(());
        }
        "-exported_symbols_list" => {
            if let Some(val) = input.next() {
                args.exported_symbols_list = Some(PathBuf::from(val.as_ref()));
            }
            return Ok(());
        }
        "-exported_symbol" => {
            if let Some(val) = input.next() {
                args.exported_symbols.push(val.as_ref().to_string());
            }
            return Ok(());
        }
        "-unexported_symbol" => {
            if let Some(val) = input.next() {
                args.unexported_symbols.push(val.as_ref().to_string());
            }
            return Ok(());
        }
        "-unexported_symbols_list" => {
            if let Some(val) = input.next() {
                args.unexported_symbols_list = Some(PathBuf::from(val.as_ref()));
            }
            return Ok(());
        }
        "-compatibility_version" => {
            if let Some(val) = input.next() {
                args.compatibility_version = parse_macho_version(val.as_ref());
            }
            return Ok(());
        }
        "-current_version" => {
            if let Some(val) = input.next() {
                args.current_version = parse_macho_version(val.as_ref());
            }
            return Ok(());
        }
        "-framework" | "-weak_framework" | "-needed_framework" => {
            if let Some(name) = input.next() {
                // Defer resolution: -F paths may come after -framework in cc invocations.
                args.pending_frameworks.push(name.as_ref().to_string());
            }
            return Ok(());
        }
        "-lto_library"
        | "-mllvm"
        | "-headerpad"
        | "-object_path_lto"
        | "-order_file"
        | "-weak_library"
        | "-reexport_library"
        | "-umbrella"
        | "-allowable_client"
        | "-client_name"
        | "-sub_library"
        | "-sub_umbrella"
        | "-objc_abi_version"
        | "-add_ast_path"
        | "-dependency_info"
        | "-map"
        | "-pagezero_size"
        | "-image_base"
        | "-oso_prefix" => {
            input.next(); // consume the argument
            return Ok(());
        }
        // -sectcreate takes 3 arguments: segname sectname file
        "-sectcreate" => {
            if let (Some(seg), Some(sect), Some(file)) =
                (input.next(), input.next(), input.next())
            {
                let mut segname = [0u8; 16];
                let mut sectname = [0u8; 16];
                let seg_bytes = seg.as_ref().as_bytes();
                let sect_bytes = sect.as_ref().as_bytes();
                segname[..seg_bytes.len().min(16)]
                    .copy_from_slice(&seg_bytes[..seg_bytes.len().min(16)]);
                sectname[..sect_bytes.len().min(16)]
                    .copy_from_slice(&sect_bytes[..sect_bytes.len().min(16)]);
                let data = std::fs::read(file.as_ref())
                    .with_context(|| format!("Failed to read -sectcreate file `{}`", file.as_ref()))?;
                args.sectcreate.push((segname, sectname, data));
            }
            return Ok(());
        }
        // -add_empty_section takes 2 arguments: segname sectname
        "-add_empty_section" => {
            if let (Some(seg), Some(sect)) = (input.next(), input.next()) {
                let mut segname = [0u8; 16];
                let mut sectname = [0u8; 16];
                let seg_bytes = seg.as_ref().as_bytes();
                let sect_bytes = sect.as_ref().as_bytes();
                segname[..seg_bytes.len().min(16)]
                    .copy_from_slice(&seg_bytes[..seg_bytes.len().min(16)]);
                sectname[..sect_bytes.len().min(16)]
                    .copy_from_slice(&sect_bytes[..sect_bytes.len().min(16)]);
                args.empty_sections.push((segname, sectname));
            }
            return Ok(());
        }
        // -platform_version takes 3 arguments: platform min_version sdk_version
        "-platform_version" => {
            input.next(); // platform (ignored, always macos)
            if let Some(v) = input.next() {
                args.minos = Some(parse_macho_version(v.as_ref()));
            }
            if let Some(v) = input.next() {
                args.sdk_version = Some(parse_macho_version(v.as_ref()));
            }
            return Ok(());
        }
        "-macos_version_min" => {
            if let Some(v) = input.next() {
                args.minos = Some(parse_macho_version(v.as_ref()));
            }
            return Ok(());
        }
        "-force_load" => {
            if let Some(val) = input.next() {
                let path = Path::new(val.as_ref());
                let mut mods = *modifier_stack.last().unwrap();
                mods.whole_archive = true;
                args.common.inputs.push(Input {
                    spec: InputSpec::File(Box::from(path)),
                    search_first: None,
                    modifiers: mods,
                });
            }
            return Ok(());
        }
        // Flags that take 1 argument, ignored (group 2)
        "-undefined" | "-multiply_defined" | "-upward-l" | "-alignment" => {
            input.next();
            return Ok(());
        }
        "-S" => {
            args.strip = Strip::Debug;
            return Ok(());
        }
        "-demangle" => {
            args.common.demangle = true;
            return Ok(());
        }
        "-export_dynamic" => {
            args.export_dynamic = true;
            return Ok(());
        }
        "-dead_strip" => {
            args.gc_sections = true;
            return Ok(());
        }
        "-search_dylibs_first" => {
            args.search_dylibs_first = true;
            return Ok(());
        }
        // No-argument flags, ignored
        "-dynamic"
        | "-no_deduplicate"
        | "-no_compact_unwind"
        | "-dead_strip_dylibs"
        | "-headerpad_max_install_names"
        | "-application_extension"
        | "-no_objc_category_merging"
        | "-mark_dead_strippable_dylib"
        | "-ObjC"
        | "-no_implicit_dylibs"
        | "-search_paths_first"
        | "-two_levelnamespace"
        | "-flat_namespace"
        | "-bind_at_load"
        | "-pie"
        | "-no_pie"
        | "-execute"
        | "-no_fixup_chains"
        | "-fixup_chains"
        | "-adhoc_codesign"
        | "-w"
        | "-Z"
        | "-data_in_code_info"
        | "-function_starts"
        | "-subsections_via_symbols"
        | "-reproducible" => {
            return Ok(());
        }
        "-all_load" => {
            modifier_stack.last_mut().unwrap().whole_archive = true;
            return Ok(());
        }
        "-noall_load" => {
            modifier_stack.last_mut().unwrap().whole_archive = false;
            return Ok(());
        }
        "-dylib" | "-dynamiclib" => {
            args.is_dylib = true;
            args.entry_symbol = None; // dylibs have no entry point
            return Ok(());
        }
        "-bundle" => {
            args.is_bundle = true;
            args.entry_symbol = None; // bundles have no entry point
            return Ok(());
        }
        "-x" => {
            args.strip_locals = true;
            return Ok(());
        }
        "-no_adhoc_codesign" => {
            args.no_adhoc_codesign = true;
            return Ok(());
        }
        "-no_function_starts" => {
            args.no_function_starts = true;
            return Ok(());
        }
        "-final_output" => {
            if let Some(val) = input.next() {
                args.final_output = Some(val.as_ref().to_string());
            }
            return Ok(());
        }
        "-no_uuid" => {
            args.no_uuid = true;
            return Ok(());
        }
        "-random_uuid" => {
            args.random_uuid = true;
            return Ok(());
        }
        "-no_data_in_code_info" => {
            args.no_data_in_code = true;
            return Ok(());
        }
        "-stack_size" => {
            if let Some(val) = input.next() {
                let val = val.as_ref();
                args.stack_size = Some(
                    u64::from_str_radix(val.strip_prefix("0x").unwrap_or(val), 16).unwrap_or(0),
                );
            }
            return Ok(());
        }
        "-r" => {
            args.is_relocatable = true;
            args.entry_symbol = None;
            return Ok(());
        }
        "--validate-output" => {
            args.common.validate_output = true;
            return Ok(());
        }
        "-filelist" => {
            if let Some(val) = input.next() {
                let val = val.as_ref();
                // -filelist <path>[,<directory>]
                let (file_path, prefix) = if let Some(comma) = val.find(',') {
                    (&val[..comma], Some(&val[comma + 1..]))
                } else {
                    (val, None)
                };
                let content = std::fs::read_to_string(file_path)
                    .with_context(|| format!("Failed to read filelist `{file_path}`"))?;
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let path = if let Some(dir) = prefix {
                        Path::new(dir).join(line)
                    } else {
                        PathBuf::from(line)
                    };
                    args.common.inputs.push(Input {
                        spec: InputSpec::File(Box::from(path.as_path())),
                        search_first: None,
                        modifiers: *modifier_stack.last().unwrap(),
                    });
                }
            }
            return Ok(());
        }
        _ => {}
    }

    // Handle --time=<value> form
    if let Some(val) = arg.strip_prefix("--time=") {
        args.common.time_phase_options = Some(super::parse_time_phase_options(val)?);
        return Ok(());
    }

    // -L<path> (library search path)
    if let Some(path) = arg.strip_prefix("-L") {
        if path.is_empty() {
            if let Some(val) = input.next() {
                args.lib_search_paths
                    .push(Box::from(Path::new(val.as_ref())));
            }
        } else {
            args.lib_search_paths.push(Box::from(Path::new(path)));
        }
        return Ok(());
    }

    // -F<path> (framework search path)
    if let Some(path) = arg.strip_prefix("-F") {
        if !path.is_empty() {
            args.framework_search_paths
                .push(Box::from(Path::new(path)));
        } else if let Some(val) = input.next() {
            args.framework_search_paths
                .push(Box::from(Path::new(val.as_ref())));
        }
        return Ok(());
    }

    // -U <symbol> (allow undefined, dynamic lookup)
    if arg == "-U" {
        input.next();
        return Ok(());
    }

    // Prefix link flags: -needed-l<name>, -weak-l<name>, -reexport-l<name>, -hidden-l<name>
    let mut dylib_kind = DylibLoadKind::Normal;
    let lib_from_prefix = if let Some(name) = arg.strip_prefix("-weak-l") {
        dylib_kind = DylibLoadKind::Weak;
        Some(name)
    } else if let Some(name) = arg.strip_prefix("-reexport-l") {
        dylib_kind = DylibLoadKind::Reexport;
        Some(name)
    } else {
        arg.strip_prefix("-needed-l")
            .or_else(|| arg.strip_prefix("-hidden-l"))
    };

    // -l<name> (link library) -- must come after -lto_library check above
    let lib_name = lib_from_prefix.or_else(|| arg.strip_prefix("-l"));
    if let Some(lib) = lib_name {
        if !lib.is_empty() {
            // On macOS, libSystem is implicitly linked (we emit LC_LOAD_DYLIB for it).
            // Skip it and other system dylibs that we handle implicitly, but still
            // parse their .tbd to know which symbols they export.
            if lib == "System" || lib == "c" || lib == "m" || lib == "pthread" {
                let mut search_paths: Vec<Box<Path>> = args.lib_search_paths.clone();
                if let Some(ref root) = args.syslibroot {
                    search_paths.push(Box::from(root.join("usr/lib")));
                }
                for dir in &search_paths {
                    let tbd_path = dir.join(format!("lib{lib}.tbd"));
                    if tbd_path.exists() {
                        collect_tbd_symbols(&tbd_path, &mut args.dylib_symbols);
                        // Also collect from re-exported libraries (e.g. libSystem
                        // re-exports libdyld, libsystem_c, etc. from system/ subdir)
                        let system_dir = dir.join("system");
                        if system_dir.is_dir() {
                            if let Ok(entries) = std::fs::read_dir(&system_dir) {
                                for entry in entries.flatten() {
                                    let p = entry.path();
                                    if p.extension().map_or(false, |e| e == "tbd") {
                                        collect_tbd_symbols(&p, &mut args.dylib_symbols);
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
                return Ok(());
            }
            // Try to find the library on the search path, including syslibroot.
            let mut found = false;
            let extensions = [".tbd", ".dylib", ".a"];
            let mut search_paths: Vec<Box<Path>> = args.lib_search_paths.clone();
            if let Some(ref root) = args.syslibroot {
                search_paths.push(Box::from(root.join("usr/lib")));
                search_paths.push(Box::from(root.join("usr/lib/swift")));
            }
            // search_paths_first (default): try all extensions per dir.
            // search_dylibs_first: try each extension across all dirs.
            let search_dylibs_first = args.search_dylibs_first;
            'search: for i in 0..extensions.len() * search_paths.len() {
                let (dir_idx, ext_idx) = if search_dylibs_first {
                    (i % search_paths.len(), i / search_paths.len())
                } else {
                    (i / extensions.len(), i % extensions.len())
                };
                let ext = extensions[ext_idx];
                let dir = &search_paths[dir_idx];
                let path = dir.join(format!("lib{lib}{ext}"));
                if path.exists() {
                    if ext == ".tbd" {
                        if let Some(dylib_path) = parse_tbd_install_name(&path) {
                            args.add_dylib(dylib_path, dylib_kind);
                        }
                        collect_tbd_symbols(&path, &mut args.dylib_symbols);
                    } else if ext == ".dylib" {
                        // Parse exports trie + install name from the dylib.
                        handle_dylib_input(args, &path)?;
                        // Override the load kind if a prefix modifier was used.
                        if dylib_kind != DylibLoadKind::Normal {
                            if let Some(last) = args.extra_dylibs.last_mut() {
                                last.1 = dylib_kind;
                            }
                        }
                    } else {
                        args.common.inputs.push(Input {
                            spec: InputSpec::File(Box::from(path.as_path())),
                            search_first: None,
                            modifiers: *modifier_stack.last().unwrap(),
                        });
                    }
                    found = true;
                    break 'search;
                }
            }
            // If not found, warn but don't error (might be a system dylib we handle implicitly)
            if !found {
                tracing::warn!("library not found: -l{lib}");
            }
        }
        return Ok(());
    }

    // Unknown flags starting with - go to unrecognized
    if arg.starts_with('-') {
        args.common.unrecognized_options.push(arg.to_owned());
        return Ok(());
    }

    // Positional argument = input file.
    // Check if it's a dylib/bundle -- if so, treat like a .tbd (extract install name
    // and symbols, emit LC_LOAD_DYLIB) rather than passing through object pipeline.
    let path = Path::new(arg);
    if path.extension().map_or(false, |e| e == "tbd") {
        // Defer: $ld$ directives depend on -platform_version which may come later.
        args.pending_tbd_inputs.push(path.to_path_buf());
    } else if path.extension().map_or(false, |e| e == "dylib")
        || is_macho_dylib(path)
    {
        handle_dylib_input(args, path)?;
    } else {
        args.common.save_dir.handle_file(arg);
        args.common.inputs.push(Input {
            spec: InputSpec::File(Box::from(path)),
            search_first: None,
            modifiers: *modifier_stack.last().unwrap(),
        });
    }

    Ok(())
}

/// Extract `install-name` from a .tbd (text-based dylib stub) file.
fn parse_tbd_install_name(path: &Path) -> Option<Vec<u8>> {
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("install-name:") {
            let name = rest.trim().trim_matches('\'').trim_matches('"');
            if !name.is_empty() {
                return Some(name.as_bytes().to_vec());
            }
        }
    }
    None
}

/// Parse a Mach-O version string like "10.9" or "13.5.1" into packed u32 format:
/// major<<16 | minor<<8 | patch.
fn parse_macho_version(s: &str) -> u32 {
    let mut parts = s.split('.');
    let major = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    let patch = parts
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);
    (major << 16) | (minor << 8) | patch
}

/// Collect exported symbols from a .tbd file, processing $ld$ linker directives.
fn collect_tbd_symbols_with_directives(
    path: &Path,
    symbols: &mut std::collections::HashSet<Vec<u8>>,
    minos: Option<u32>,
    install_name: &mut Option<Vec<u8>>,
) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let records = match text_stub_library::parse_str(&content) {
        Ok(r) => r,
        Err(_) => return,
    };
    let target_version = minos.unwrap_or(0);
    let mut hide_list = Vec::new();
    for record in &records {
        match record {
            text_stub_library::TbdVersionedRecord::V4(v4) => {
                let is_arm64 = |targets: &[String]| -> bool {
                    targets.is_empty()
                        || targets
                            .iter()
                            .any(|t| t.starts_with("arm64-") || t.starts_with("arm64e-"))
                };
                for exp in &v4.exports {
                    if !is_arm64(&exp.targets) {
                        continue;
                    }
                    for sym in exp.symbols.iter().chain(exp.weak_symbols.iter()) {
                        process_tbd_symbol(sym, symbols, target_version, install_name, &mut hide_list);
                    }
                }
                for exp in &v4.re_exports {
                    if !is_arm64(&exp.targets) {
                        continue;
                    }
                    for sym in &exp.symbols {
                        process_tbd_symbol(sym, symbols, target_version, install_name, &mut hide_list);
                    }
                }
            }
            text_stub_library::TbdVersionedRecord::V3(v3) => {
                for exp in &v3.exports {
                    for sym in &exp.symbols {
                        process_tbd_symbol(sym, symbols, target_version, install_name, &mut hide_list);
                    }
                }
            }
            _ => {}
        }
    }
    // Apply hide directives after all symbols are collected.
    for sym in &hide_list {
        symbols.remove(sym);
    }
}

/// Process a single symbol from a .tbd, handling $ld$ linker directives.
/// Returns Some(sym_name) for $ld$hide$ directives to remove in a second pass.
fn process_tbd_symbol(
    sym: &str,
    symbols: &mut std::collections::HashSet<Vec<u8>>,
    target_version: u32,
    install_name: &mut Option<Vec<u8>>,
    hide_list: &mut Vec<Vec<u8>>,
) {
    if let Some(rest) = sym.strip_prefix("$ld$add$os") {
        // $ld$add$os<ver>$_<sym> — add symbol if target >= ver
        if let Some((ver_str, _real_sym)) = rest.split_once('$') {
            let ver = parse_macho_version(ver_str);
            if target_version >= ver {
                if let Some(real) = rest.rsplit_once('$') {
                    symbols.insert(real.1.as_bytes().to_vec());
                }
            }
        }
    } else if let Some(rest) = sym.strip_prefix("$ld$hide$os") {
        // $ld$hide$os<ver>$_<sym> — hide symbol if target >= ver (deferred)
        if let Some((ver_str, real_sym)) = rest.split_once('$') {
            let ver = parse_macho_version(ver_str);
            if target_version >= ver {
                hide_list.push(real_sym.as_bytes().to_vec());
            }
        }
    } else if let Some(rest) = sym.strip_prefix("$ld$install_name$os") {
        // $ld$install_name$os<ver>$<new_name> — change install name if target >= ver
        if let Some((ver_str, new_name)) = rest.split_once('$') {
            let ver = parse_macho_version(ver_str);
            if target_version >= ver {
                *install_name = Some(new_name.as_bytes().to_vec());
            }
        }
    } else if let Some(rest) = sym.strip_prefix("$ld$previous$") {
        // $ld$previous$<install_name>$$<compat_ver>$<min_os>$<max_os>$$
        // Use <install_name> when target is in [min_os, max_os)
        let parts: Vec<&str> = rest.split('$').collect();
        // Format: <name> "" <compat> <min> <max> ""
        if parts.len() >= 5 {
            let new_name = parts[0];
            let min_os = parse_macho_version(parts[3]);
            let max_os = parse_macho_version(parts[4]);
            if target_version >= min_os && (max_os == 0 || target_version < max_os) {
                *install_name = Some(new_name.as_bytes().to_vec());
            }
        }
    } else {
        // Regular symbol
        symbols.insert(sym.as_bytes().to_vec());
    }
}

/// Collect exported symbols from a .tbd file into the given set (no directive processing).
fn collect_tbd_symbols(path: &Path, symbols: &mut std::collections::HashSet<Vec<u8>>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let records = match text_stub_library::parse_str(&content) {
        Ok(r) => r,
        Err(_) => return,
    };
    for record in &records {
        match record {
            text_stub_library::TbdVersionedRecord::V4(v4) => {
                let is_arm64 = |targets: &[String]| -> bool {
                    targets.is_empty()
                        || targets
                            .iter()
                            .any(|t| t.starts_with("arm64-") || t.starts_with("arm64e-"))
                };
                for exp in &v4.exports {
                    if !is_arm64(&exp.targets) {
                        continue;
                    }
                    for sym in &exp.symbols {
                        symbols.insert(sym.as_bytes().to_vec());
                    }
                    for sym in &exp.weak_symbols {
                        symbols.insert(sym.as_bytes().to_vec());
                    }
                }
                for exp in &v4.re_exports {
                    if !is_arm64(&exp.targets) {
                        continue;
                    }
                    for sym in &exp.symbols {
                        symbols.insert(sym.as_bytes().to_vec());
                    }
                }
            }
            text_stub_library::TbdVersionedRecord::V3(v3) => {
                for exp in &v3.exports {
                    for sym in &exp.symbols {
                        symbols.insert(sym.as_bytes().to_vec());
                    }
                }
            }
            _ => {}
        }
    }
}

/// Search framework search paths for a framework and register it as a dylib dependency.
fn link_framework(args: &mut MachOArgs, name: &str) -> Result {
    // Search: <F-path>/<name>.framework/<name>[.tbd]
    let framework_dir = format!("{name}.framework");
    for dir in &args.framework_search_paths {
        let fw_dir = dir.join(&framework_dir);
        if !fw_dir.is_dir() {
            continue;
        }
        // Try .tbd first, then bare name (dylib without extension)
        let tbd_path = fw_dir.join(format!("{name}.tbd"));
        if tbd_path.exists() {
            if let Some(dylib_path) = parse_tbd_install_name(&tbd_path) {
                args.add_dylib(dylib_path, DylibLoadKind::Normal);
            }
            collect_tbd_symbols(&tbd_path, &mut args.dylib_symbols);
            return Ok(());
        }
        let dylib_path = fw_dir.join(name);
        if dylib_path.exists() {
            let install = dylib_path.to_string_lossy().as_bytes().to_vec();
            args.add_dylib(install, DylibLoadKind::Normal);
            return Ok(());
        }
    }
    tracing::warn!("framework not found: {name}");
    Ok(())
}

/// Check if a file is a Mach-O dylib/bundle by reading its header.
fn is_macho_dylib(path: &Path) -> bool {
    let Ok(data) = std::fs::read(path) else {
        return false;
    };
    if data.len() < 16 {
        return false;
    }
    let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
    if magic != 0xfeed_facf {
        return false;
    }
    let filetype = u32::from_le_bytes(data[12..16].try_into().unwrap());
    matches!(filetype, 6 | 8) // MH_DYLIB | MH_BUNDLE
}

/// Handle a .tbd file as a positional input: extract install-name and symbols, register as dylib dep.
fn handle_tbd_input(args: &mut MachOArgs, path: &Path) -> Result {
    let mut install_name = parse_tbd_install_name(path);
    collect_tbd_symbols_with_directives(path, &mut args.dylib_symbols, args.minos, &mut install_name);
    if let Some(name) = install_name {
        args.add_dylib(name, DylibLoadKind::Normal);
    }
    Ok(())
}

/// Handle a .dylib input: extract install name and exported symbols, register as dylib dep.
fn handle_dylib_input(args: &mut MachOArgs, path: &Path) -> Result {
    let data = std::fs::read(path)
        .with_context(|| format!("Failed to read dylib `{}`", path.display()))?;
    let le = object::Endianness::Little;

    // Parse install name from LC_ID_DYLIB
    let mut install_name: Option<Vec<u8>> = None;
    let mut exported_symbols: Vec<Vec<u8>> = Vec::new();

    if data.len() >= 32 {
        let ncmds = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;
        let mut offset = 32; // skip mach_header_64 (32 bytes)
        for _ in 0..ncmds {
            if offset + 8 > data.len() {
                break;
            }
            let cmd = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
            let cmdsize = u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
            if cmdsize < 8 || offset + cmdsize > data.len() {
                break;
            }
            // LC_ID_DYLIB = 0x0D
            if cmd == 0x0D && cmdsize >= 24 {
                let name_offset = u32::from_le_bytes(
                    data[offset + 8..offset + 12].try_into().unwrap(),
                ) as usize;
                if name_offset < cmdsize {
                    let name_start = offset + name_offset;
                    let name_end = data[name_start..]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| name_start + p)
                        .unwrap_or(offset + cmdsize);
                    install_name = Some(data[name_start..name_end].to_vec());
                }
            }
            // LC_DYLD_EXPORTS_TRIE = 0x80000033 or LC_DYLD_INFO[_ONLY] = 0x22 / 0x80000022
            if (cmd == 0x8000_0033) && cmdsize >= 16 {
                let trie_off = u32::from_le_bytes(
                    data[offset + 8..offset + 12].try_into().unwrap(),
                ) as usize;
                let trie_size = u32::from_le_bytes(
                    data[offset + 12..offset + 16].try_into().unwrap(),
                ) as usize;
                if trie_off > 0 && trie_size > 0 && trie_off + trie_size <= data.len() {
                    parse_export_trie(&data[trie_off..trie_off + trie_size], &mut exported_symbols);
                }
            }
            // LC_DYLD_INFO / LC_DYLD_INFO_ONLY: export info is at fields [40..48]
            if (cmd == 0x22 || cmd == 0x8000_0022) && cmdsize >= 48 {
                let export_off = u32::from_le_bytes(
                    data[offset + 40..offset + 44].try_into().unwrap(),
                ) as usize;
                let export_size = u32::from_le_bytes(
                    data[offset + 44..offset + 48].try_into().unwrap(),
                ) as usize;
                if export_off > 0 && export_size > 0 && export_off + export_size <= data.len() {
                    parse_export_trie(
                        &data[export_off..export_off + export_size],
                        &mut exported_symbols,
                    );
                }
            }
            offset += cmdsize;
        }
    }

    let name = install_name.unwrap_or_else(|| path.to_string_lossy().as_bytes().to_vec());
    args.add_dylib(name, DylibLoadKind::Normal);
    for sym in exported_symbols {
        args.dylib_symbols.insert(sym);
    }
    Ok(())
}

/// Walk a Mach-O exports trie and collect all symbol names.
fn parse_export_trie(trie: &[u8], symbols: &mut Vec<Vec<u8>>) {
    fn walk(trie: &[u8], offset: usize, prefix: &[u8], symbols: &mut Vec<Vec<u8>>) {
        if offset >= trie.len() {
            return;
        }
        let mut pos = offset;
        // Terminal info size (ULEB128)
        let (terminal_size, n) = read_uleb128(&trie[pos..]);
        pos += n;
        if terminal_size > 0 {
            // This node is a terminal — the prefix is an exported symbol
            symbols.push(prefix.to_vec());
        }
        let terminal_end = pos + terminal_size as usize;
        if terminal_end > trie.len() {
            return;
        }
        pos = terminal_end;
        // Child count
        if pos >= trie.len() {
            return;
        }
        let child_count = trie[pos] as usize;
        pos += 1;
        for _ in 0..child_count {
            // Edge label (NUL-terminated string)
            let label_start = pos;
            while pos < trie.len() && trie[pos] != 0 {
                pos += 1;
            }
            let label = &trie[label_start..pos];
            if pos < trie.len() {
                pos += 1; // skip NUL
            }
            // Child node offset (ULEB128)
            let (child_offset, n) = read_uleb128(&trie[pos..]);
            pos += n;
            let mut child_prefix = prefix.to_vec();
            child_prefix.extend_from_slice(label);
            walk(trie, child_offset as usize, &child_prefix, symbols);
        }
    }

    walk(trie, 0, &[], symbols);
}

fn read_uleb128(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return (result, i + 1);
        }
        shift += 7;
    }
    (result, data.len())
}
