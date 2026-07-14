#![allow(unused)]

use crate::alignment::Alignment;
use crate::args::ArgumentParser;
use crate::args::CommonArgs;
use crate::args::FILES_PER_GROUP_ENV;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::args::REFERENCE_LINKER_ENV;
use crate::args::RelocationModel;
use crate::ensure;
use crate::error::Result;
use crate::platform;
use crate::save_dir::SaveDir;
use jobserver::Client;
use std::path::Path;
use std::sync::Arc;

/// Loadable segment alignment for wasm. Wasm doesn't really have program
/// segments in the ELF sense, but we still need to provide a value for the
/// `Args` trait.
pub(crate) const WASM_PAGE_ALIGNMENT: Alignment = Alignment { exponent: 16 };

/// Default page size (in bytes) for a wasm linear memory page.
pub(crate) const WASM_PAGE_SIZE: u64 = WASM_PAGE_ALIGNMENT.value();

#[derive(Debug)]
pub struct WasmArgs {
    pub(crate) common: super::CommonArgs,
    pub(crate) lib_search_path: Vec<Box<Path>>,
}

impl WasmArgs {
    pub(crate) fn new() -> Result<Self> {
        Ok(Self {
            common: CommonArgs::from_env()?,
            ..Default::default()
        })
    }
}

#[expect(clippy::derivable_impls)]
impl Default for WasmArgs {
    fn default() -> Self {
        Self {
            common: CommonArgs::default(),
            lib_search_path: Vec::new(),
        }
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
        todo!()
    }

    fn should_strip_all(&self) -> bool {
        false
    }

    fn entry_symbol_name<'a>(&'a self, linker_script_entry: Option<&'a [u8]>) -> &'a [u8] {
        // TODO: probably add option. wasm-ld defaults to `_start` for command
        // modules and no entry for reactor modules.
        b"_start"
    }

    fn lib_search_path(&self) -> &[Box<std::path::Path>] {
        &self.lib_search_path
    }

    fn common(&self) -> &crate::args::CommonArgs {
        &self.common
    }

    fn common_mut(&mut self) -> &mut crate::args::CommonArgs {
        &mut self.common
    }

    fn should_export_all_dynamic_symbols(&self) -> bool {
        todo!()
    }

    fn should_export_dynamic(&self, lib_name: &[u8]) -> bool {
        todo!()
    }

    fn loadable_segment_alignment(&self) -> crate::alignment::Alignment {
        WASM_PAGE_ALIGNMENT
    }

    fn should_merge_sections(&self) -> bool {
        // TODO
        true
    }

    fn should_output_executable(&self) -> bool {
        // TODO
        true
    }

    fn is_ignored_flag(&self, _flag: &str) -> bool {
        false
    }
}

pub(crate) fn parse<S: AsRef<str>, I: Iterator<Item = S>>(
    args: &mut WasmArgs,
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

fn setup_argument_parser() -> ArgumentParser<WasmArgs> {
    let mut parser = ArgumentParser::<WasmArgs>::new();

    parser
        .declare_with_param()
        .long("output")
        .short("o")
        .help("Set the output filename")
        .execute(|args, _modifier_stack, value| {
            args.common.output = Arc::from(Path::new(value));
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("L")
        .help("Add directory to library search path")
        .execute(|args, _modifier_stack, value| {
            args.common.save_dir.handle_file(value);
            args.lib_search_path.push(Box::from(Path::new(value)));
            Ok(())
        });

    parser
        .declare_with_param()
        .prefix("l")
        .help("Link with library")
        .execute(|args, modifier_stack, value| {
            // Prefer static archives. Wasm has no shared-object loading.
            let mut modifiers = *modifier_stack.last().unwrap();
            modifiers.allow_shared = false;
            let spec = if let Some(stripped) = value.strip_prefix(':') {
                InputSpec::Search(Box::from(stripped))
            } else {
                InputSpec::Lib(Box::from(value))
            };
            args.common.inputs.push(Input {
                spec,
                search_first: None,
                modifiers,
            });
            Ok(())
        });

    parser
        .declare()
        .long("no-gc-sections")
        .help("Disable removal of unused sections")
        .execute(|_args, _modifier_stack| {
            // TODO
            Ok(())
        });

    super::declare_common_args(&mut parser);

    parser
}
