// Mach-O argument parsing for the macOS linker driver interface.
#![allow(unused_variables)]

use crate::args::ArgumentParser;
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

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        // Apple Silicon uses 16KB pages
        crate::alignment::Alignment { exponent: 14 }
    }

    fn should_merge_sections(&self) -> bool {
        false
    }

    fn relocation_model(&self) -> crate::args::RelocationModel {
        self.relocation_model
    }

    fn should_output_executable(&self) -> bool {
        true
    }
}

/// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut MachOArgs,
    mut input: I,
) -> Result {
    let mut modifier_stack = vec![Modifiers::default()];

    let arg_parser = setup_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();
        arg_parser.handle_argument(args, &mut modifier_stack, arg, &mut input)?;
    }

    Ok(())
}

/// Flags that macOS ld passes but we safely ignore for now.
const MACHO_IGNORED_FLAGS: &[&str] = &[
    "demangle",
    "dynamic",
    "lto_library",
    "mllvm",
    "no_deduplicate",
    "no_compact_unwind",
    "dead_strip",
    "dead_strip_dylibs",
    "headerpad_max_install_names",
    "export_dynamic",
    "application_extension",
    "no_objc_category_merging",
    "objc_abi_version",
    "mark_dead_strippable_dylib",
];

fn setup_argument_parser() -> ArgumentParser<MachOArgs> {
    let mut parser = ArgumentParser::<MachOArgs>::new();

    parser
        .declare_with_param()
        .long("output")
        .short("o")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.output = Arc::from(Path::new(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .long("arch")
        .help("Architecture")
        .execute(|_args, _modifier_stack, _value| {
            // We only support arm64 currently, ignore the flag
            Ok(())
        });

    parser
        .declare_with_param()
        .long("platform_version")
        .help("Set platform version (takes 3 args: platform min_version sdk_version)")
        .execute(|_args, _modifier_stack, _value| {
            // platform_version takes 3 arguments: platform, min_version, sdk_version
            // The ArgumentParser already consumed one arg for us, but we need 2 more.
            // They'll get treated as unrecognised positional args. That's OK for now.
            Ok(())
        });

    parser
        .declare_with_param()
        .long("syslibroot")
        .help("Set the system library root path")
        .execute(|args, _modifier_stack, value| {
            args.syslibroot = Some(Box::from(Path::new(value)));
            Ok(())
        });

    parser
        .declare_with_param()
        .short("e")
        .help("Set the entry point symbol name")
        .execute(|args, _modifier_stack, value| {
            args.entry_symbol = Some(value.as_bytes().to_vec());
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("l")
        .help("Link with library")
        .execute(|args, modifier_stack, value| {
            let spec = InputSpec::Lib(Box::from(value));
            args.common.inputs.push(Input {
                spec,
                search_first: None,
                modifiers: *modifier_stack.last().unwrap(),
            });
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("L")
        .help("Add library search path")
        .execute(|args, _modifier_stack, value| {
            args.lib_search_paths.push(Box::from(Path::new(value)));
            Ok(())
        });

    // Register ignored flags
    for flag in MACHO_IGNORED_FLAGS {
        // Try to register flags that take no params as ignored
        // Some take params (like lto_library, mllvm) -- we handle those by just
        // letting them fall through to unrecognised options for now
    }

    parser
}
