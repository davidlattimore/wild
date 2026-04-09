// Mach-O argument parsing for the macOS linker driver interface.
#![allow(unused_variables)]

use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::args::RelocationModel;
use crate::error::Context as _;
use crate::error::Result;
use crate::platform;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub struct MachOArgs {
    pub(crate) common: super::CommonArgs,
    pub(crate) output: Arc<Path>,
    pub(crate) relocation_model: RelocationModel,
    pub(crate) lib_search_paths: Vec<Box<Path>>,
    pub(crate) syslibroot: Option<Box<Path>>,
    pub(crate) entry_symbol: Option<Vec<u8>>,
    pub(crate) explicit_entry: bool,
    pub(crate) is_dylib: bool,
    pub(crate) is_relocatable: bool,
    #[allow(dead_code)]
    pub(crate) install_name: Option<Vec<u8>>,
    /// Additional dylibs to emit LC_LOAD_DYLIB for (from -l flags resolving to .tbd stubs).
    pub(crate) extra_dylibs: Vec<Vec<u8>>,
    /// Symbols to force as undefined (-u flag), triggering archive member loading.
    pub(crate) force_undefined: Vec<String>,
    /// Symbols exported by linked dylibs (from .tbd parsing). Used to distinguish
    /// undefined symbols that are dylib imports from truly missing symbols.
    pub(crate) dylib_symbols: std::collections::HashSet<Vec<u8>>,
}

impl MachOArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
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
            is_dylib: false,
            is_relocatable: false,
            install_name: None,
            extra_dylibs: Vec::new(),
            force_undefined: Vec::new(),
            dylib_symbols: Default::default(),
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
        false
    }
    fn should_strip_all(&self) -> bool {
        false
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
        false
    }
    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool {
        false
    }

    fn force_undefined_symbol_names(&self) -> &[String] {
        &self.force_undefined
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        crate::alignment::Alignment { exponent: 14 } // 16KB pages
    }

    fn should_merge_sections(&self) -> bool {
        false
    }

    fn relocation_model(&self) -> crate::args::RelocationModel {
        self.relocation_model
    }

    fn should_output_executable(&self) -> bool {
        !self.is_dylib && !self.is_relocatable
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
        "-lto_library"
        | "-mllvm"
        | "-headerpad"
        | "-install_name"
        | "-compatibility_version"
        | "-current_version"
        | "-rpath"
        | "-object_path_lto"
        | "-order_file"
        | "-exported_symbols_list"
        | "-unexported_symbols_list"
        | "-framework"
        | "-weak_framework"
        | "-weak_library"
        | "-reexport_library"
        | "-umbrella"
        | "-allowable_client"
        | "-client_name"
        | "-sub_library"
        | "-sub_umbrella"
        | "-objc_abi_version"
        | "-add_ast_path"
        | "-macos_version_min"
        | "-dependency_info"
        | "-map"
        | "-stack_size"
        | "-pagezero_size"
        | "-image_base"
        | "-final_output"
        | "-oso_prefix"
        | "-needed_framework" => {
            input.next(); // consume the argument
            return Ok(());
        }
        // -sectcreate takes 3 arguments: segname sectname file
        "-sectcreate" => {
            input.next(); // segname
            input.next(); // sectname
            input.next(); // file
            return Ok(());
        }
        // -add_empty_section takes 2 arguments: segname sectname
        "-add_empty_section" => {
            input.next(); // segname
            input.next(); // sectname
            return Ok(());
        }
        // -platform_version takes 3 arguments: platform min_version sdk_version
        "-platform_version" => {
            input.next(); // platform
            input.next(); // min_version
            input.next(); // sdk_version
            return Ok(());
        }
        // Flags that take 1 argument, ignored (group 2)
        "-undefined" | "-multiply_defined" | "-force_load" | "-upward-l" | "-alignment" => {
            input.next();
            return Ok(());
        }
        // No-argument flags, ignored
        "-demangle"
        | "-dynamic"
        | "-no_deduplicate"
        | "-no_compact_unwind"
        | "-dead_strip"
        | "-dead_strip_dylibs"
        | "-headerpad_max_install_names"
        | "-export_dynamic"
        | "-application_extension"
        | "-no_objc_category_merging"
        | "-mark_dead_strippable_dylib"
        | "-ObjC"
        | "-no_implicit_dylibs"
        | "-search_paths_first"
        | "-search_dylibs_first"
        | "-two_levelnamespace"
        | "-flat_namespace"
        | "-bind_at_load"
        | "-pie"
        | "-no_pie"
        | "-execute"
        | "-bundle"
        | "-no_function_starts"
        | "-no_fixup_chains"
        | "-fixup_chains"
        | "-no_adhoc_codesign"
        | "-adhoc_codesign"
        | "-S"
        | "-x"
        | "-w"
        | "-Z"
        | "-data_in_code_info"
        | "-no_data_in_code_info"
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

    // -F<path> (framework search path) — ignore for now
    if arg.strip_prefix("-F").is_some() {
        return Ok(());
    }

    // -U <symbol> (allow undefined, dynamic lookup)
    if arg == "-U" {
        input.next();
        return Ok(());
    }

    // Prefix link flags: -hidden-l<name>, -needed-l<name>, -reexport-l<name>, -weak-l<name>
    if arg.starts_with("-hidden-l")
        || arg.starts_with("-needed-l")
        || arg.starts_with("-reexport-l")
        || arg.starts_with("-weak-l")
    {
        return Ok(());
    }

    // -l<name> (link library) -- must come after -lto_library check above
    if let Some(lib) = arg.strip_prefix("-l") {
        if !lib.is_empty() {
            // On macOS, libSystem is implicitly linked (we emit LC_LOAD_DYLIB for it).
            // Skip it and other system dylibs that we handle implicitly, but still
            // parse their .tbd to know which symbols they export.
            if lib == "System" || lib == "c" || lib == "m" || lib == "pthread" {
                // Still parse .tbd for symbol resolution (including re-exported libs)
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
            // Try to find the library on the search path, including syslibroot
            let mut found = false;
            let extensions = [".tbd", ".dylib", ".a"];
            let mut search_paths: Vec<Box<Path>> = args.lib_search_paths.clone();
            if let Some(ref root) = args.syslibroot {
                search_paths.push(Box::from(root.join("usr/lib")));
                search_paths.push(Box::from(root.join("usr/lib/swift")));
            }
            for ext in &extensions {
                let filename = format!("lib{lib}{ext}");
                for dir in &search_paths {
                    let path = dir.join(&filename);
                    if path.exists() {
                        // .tbd files are text-based dylib stubs. Parse the
                        // install-name so we can emit LC_LOAD_DYLIB for it.
                        if *ext == ".tbd" {
                            if let Some(dylib_path) = parse_tbd_install_name(&path) {
                                if !args.extra_dylibs.contains(&dylib_path) {
                                    args.extra_dylibs.push(dylib_path);
                                }
                            }
                            collect_tbd_symbols(&path, &mut args.dylib_symbols);
                            found = true;
                            break;
                        }
                        if *ext == ".dylib" {
                            // For .dylib files found via -l, emit LC_LOAD_DYLIB
                            // using the file's install name (from LC_ID_DYLIB).
                            // For simplicity, use the path as the install name.
                            let install = path.to_string_lossy().as_bytes().to_vec();
                            if !args.extra_dylibs.contains(&install) {
                                args.extra_dylibs.push(install);
                            }
                            found = true;
                            break;
                        }
                        args.common.inputs.push(Input {
                            spec: InputSpec::File(Box::from(path.as_path())),
                            search_first: None,
                            modifiers: *modifier_stack.last().unwrap(),
                        });
                        found = true;
                        break;
                    }
                }
                if found {
                    break;
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

    // Positional argument = input file
    args.common.save_dir.handle_file(arg);
    args.common.inputs.push(Input {
        spec: InputSpec::File(Box::from(Path::new(arg))),
        search_first: None,
        modifiers: *modifier_stack.last().unwrap(),
    });

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

/// Collect exported symbols from a .tbd file into the given set.
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
