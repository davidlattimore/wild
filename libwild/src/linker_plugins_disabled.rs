#![allow(dead_code)]
#![allow(clippy::unused_self)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::needless_pass_by_ref_mut)]

use crate::error::Result;
use crate::input_data::FileLoader;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_section_id::OutputSections;
use crate::resolution::Resolver;
use crate::symbol_db::SymbolDb;
use crate::value_flags::PerSymbolFlags;
use std::marker::PhantomData;

pub(crate) struct LoadedPlugin {}

pub(crate) struct LinkerPlugin<'data> {
    _phantom: PhantomData<&'data u8>,
}

pub(crate) struct LtoInputInfo<'data> {
    _phantom: PhantomData<&'data u8>,
}

pub(crate) struct PluginOutputs {}

impl<'data> LinkerPlugin<'data> {
    pub(crate) fn process_input(
        &self,
        _input_ref: crate::input_data::InputRef<'_>,
        _file: &std::fs::File,
        _kind: crate::file_kind::FileKind,
    ) -> Result<Box<LtoInputInfo<'data>>> {
        unreachable!();
    }

    pub(crate) fn from_args(
        _args: &'data crate::Args,
        _linker_plugin_arena: &colosseum::sync::Arena<LoadedPlugin>,
        _herd: &bumpalo_herd::Herd,
    ) -> Result<Option<Self>> {
        Ok(None)
    }

    pub(crate) fn is_initialised(&self) -> bool {
        false
    }

    pub(crate) fn all_symbols_read(
        &mut self,
        _symbol_db: &mut SymbolDb<'data, crate::elf::File<'data>>,
        _resolver: &mut Resolver<'data, crate::elf::File<'data>>,
        _file_loader: &mut FileLoader<'data>,
        _per_symbol_flags: &mut PerSymbolFlags,
        _output_sections: &mut OutputSections<'data>,
        _layout_rules_builder: &mut LayoutRulesBuilder<'data>,
    ) -> Result {
        Ok(())
    }
}
