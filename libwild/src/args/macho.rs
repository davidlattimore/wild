// TODO
#![allow(unused_variables)]
#![allow(unused)]

use crate::args::ArgumentParser;
use crate::args::CommonArgs;
use crate::args::FILES_PER_GROUP_ENV;
use crate::args::Modifiers;
use crate::args::REFERENCE_LINKER_ENV;
use crate::ensure;
use crate::error::Result;
use crate::platform;
use crate::save_dir::SaveDir;
use jobserver::Client;

#[derive(Debug, Default)]
pub struct MachOArgs {
    pub(crate) common: super::CommonArgs,
}

impl platform::Args for MachOArgs {
    fn should_strip_debug(&self) -> bool {
        todo!()
    }

    fn should_strip_all(&self) -> bool {
        todo!()
    }

    fn entry_symbol_name<'a>(&'a self, linker_script_entry: Option<&'a [u8]>) -> &'a [u8] {
        todo!()
    }

    fn lib_search_path(&self) -> &[Box<std::path::Path>] {
        todo!()
    }

    fn output(&self) -> &std::sync::Arc<std::path::Path> {
        todo!()
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
        todo!()
    }

    fn should_merge_sections(&self) -> bool {
        todo!()
    }

    fn relocation_model(&self) -> crate::args::RelocationModel {
        todo!()
    }

    fn should_output_executable(&self) -> bool {
        todo!()
    }
}

// Parse the supplied input arguments, which should not include the program name.
pub(crate) fn parse<F: Fn() -> I, S: AsRef<str>, I: Iterator<Item = S>>(
    input: F,
) -> Result<MachOArgs> {
    use crate::input_data::MAX_FILES_PER_GROUP;

    // SAFETY: Should be called early before other descriptors are opened and
    // so we open it before the arguments are parsed (can open a file).
    let jobserver_client = unsafe { Client::from_env() };

    let files_per_group = std::env::var(FILES_PER_GROUP_ENV)
        .ok()
        .map(|s| s.parse())
        .transpose()?;

    if let Some(x) = files_per_group {
        ensure!(
            x <= MAX_FILES_PER_GROUP,
            "{FILES_PER_GROUP_ENV}={x} but maximum is {MAX_FILES_PER_GROUP}"
        );
    }

    let mut args = MachOArgs {
        common: CommonArgs {
            files_per_group,
            jobserver_client,
            ..Default::default()
        },
        ..Default::default()
    };

    args.common.save_dir = SaveDir::new(&input)?;

    let mut input = input();

    let mut modifier_stack = vec![Modifiers::default()];

    if std::env::var(REFERENCE_LINKER_ENV).is_ok() {
        args.common.write_layout = true;
        args.common.write_trace = true;
    }

    let arg_parser = setup_argument_parser();
    while let Some(arg) = input.next() {
        let arg = arg.as_ref();

        arg_parser.handle_argument(&mut args, &mut modifier_stack, arg, &mut input)?;
    }

    Ok(args)
}

fn setup_argument_parser() -> ArgumentParser<MachOArgs> {
    ArgumentParser::<MachOArgs>::new()
}
