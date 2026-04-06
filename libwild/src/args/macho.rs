// Mach-O argument parsing for the macOS linker driver interface.
#![allow(unused_variables)]

use crate::args::CommonArgs;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::args::RelocationModel;
use crate::error::Result;
use crate::platform;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub struct MachOArgs {
    pub(crate) common: super::CommonArgs,
    pub(crate) output: Arc<Path>,
    pub(crate) relocation_model: RelocationModel,
    pub(crate) lib_search_paths: Vec<Box<Path>>,
    pub(crate) syslibroot: Option<Box<Path>>,
    pub(crate) entry_symbol: Option<Vec<u8>>,
    pub(crate) is_dylib: bool,
    pub(crate) install_name: Option<Vec<u8>>,
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
            is_dylib: false,
            install_name: None,
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

    fn should_strip_debug(&self) -> bool { false }
    fn should_strip_all(&self) -> bool { false }

    fn entry_symbol_name<'a>(&'a self, linker_script_entry: Option<&'a [u8]>) -> &'a [u8] {
        linker_script_entry
            .or(self.entry_symbol.as_deref())
            .unwrap_or(b"_main")
    }

    fn lib_search_path(&self) -> &[Box<std::path::Path>] {
        &self.lib_search_paths
    }

    fn output(&self) -> &std::sync::Arc<std::path::Path> { &self.output }
    fn common(&self) -> &crate::args::CommonArgs { &self.common }
    fn common_mut(&mut self) -> &mut crate::args::CommonArgs { &mut self.common }
    fn should_export_all_dynamic_symbols(&self) -> bool { false }
    fn should_export_dynamic(&self, _lib_name: &[u8]) -> bool { false }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        crate::alignment::Alignment { exponent: 14 } // 16KB pages
    }

    fn base_address(&self, _output_kind: crate::output_kind::OutputKind) -> u64 {
        if self.is_dylib {
            0 // dylibs have no PAGEZERO
        } else {
            0x1_0000_0000 // PAGEZERO size
        }
    }

    fn should_merge_sections(&self) -> bool { false }

    fn relocation_model(&self) -> crate::args::RelocationModel {
        self.relocation_model
    }

    fn should_output_executable(&self) -> bool { !self.is_dylib }
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
        "-arch" => { input.next(); return Ok(()); } // consume and ignore
        "-syslibroot" => {
            if let Some(val) = input.next() {
                args.syslibroot = Some(Box::from(Path::new(val.as_ref())));
            }
            return Ok(());
        }
        "-e" => {
            if let Some(val) = input.next() {
                args.entry_symbol = Some(val.as_ref().as_bytes().to_vec());
            }
            return Ok(());
        }
        // Flags that take 1 argument, ignored
        "-lto_library" | "-mllvm" | "-headerpad" | "-install_name"
        | "-compatibility_version" | "-current_version" | "-rpath"
        | "-object_path_lto" | "-order_file" | "-exported_symbols_list"
        | "-unexported_symbols_list" | "-filelist" | "-sectcreate"
        | "-framework" | "-weak_framework" | "-weak_library"
        | "-reexport_library" | "-umbrella" | "-allowable_client"
        | "-client_name" | "-sub_library" | "-sub_umbrella"
        | "-objc_abi_version" => {
            input.next(); // consume the argument
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
        "-undefined" | "-multiply_defined" | "-force_load" | "-weak-l"
        | "-needed-l" | "-reexport-l" | "-upward-l" | "-alignment" => {
            input.next();
            return Ok(());
        }
        // No-argument flags, ignored
        "-demangle" | "-dynamic" | "-no_deduplicate" | "-no_compact_unwind"
        | "-dead_strip" | "-dead_strip_dylibs" | "-headerpad_max_install_names"
        | "-export_dynamic" | "-application_extension" | "-no_objc_category_merging"
        | "-mark_dead_strippable_dylib" | "-ObjC" | "-all_load"
        | "-no_implicit_dylibs" | "-search_paths_first" | "-two_levelnamespace"
        | "-flat_namespace" | "-bind_at_load"
        | "-pie" | "-no_pie" | "-execute" | "-bundle" => {
            return Ok(());
        }
        "-dylib" | "-dynamiclib" => {
            args.is_dylib = true;
            args.entry_symbol = None; // dylibs have no entry point
            return Ok(());
        }
        _ => {}
    }

    // -L<path> (library search path)
    if let Some(path) = arg.strip_prefix("-L") {
        if path.is_empty() {
            if let Some(val) = input.next() {
                args.lib_search_paths.push(Box::from(Path::new(val.as_ref())));
            }
        } else {
            args.lib_search_paths.push(Box::from(Path::new(path)));
        }
        return Ok(());
    }

    // -l<name> (link library) -- must come after -lto_library check above
    if let Some(lib) = arg.strip_prefix("-l") {
        if !lib.is_empty() {
            // On macOS, libSystem is implicitly linked (we emit LC_LOAD_DYLIB for it).
            // Skip it and other system dylibs that we handle implicitly.
            if lib == "System" || lib == "c" || lib == "m" || lib == "pthread" {
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
                        // For .tbd files, skip (text-based stubs, dylib references)
                        if *ext == ".tbd" {
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
                if found { break; }
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
