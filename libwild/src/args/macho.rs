// TODO
#![allow(unused_variables)]

use crate::platform;

#[derive(Debug)]
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
        todo!()
    }

    fn common_mut(&mut self) -> &mut crate::args::CommonArgs {
        todo!()
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
