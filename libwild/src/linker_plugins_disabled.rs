#![allow(dead_code)]
#![allow(clippy::unused_self)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::needless_pass_by_ref_mut)]

use crate::args::elf::ElfArgs;
use crate::elf::Elf;
use crate::elf::ElfClass;
use crate::error::Result;
use crate::fs::FileSystem;
use crate::input_data::FileLoader;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_section_id::OutputSections;
use crate::resolution::Resolver;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::value_flags::PerSymbolFlags;
use rayon::Scope;
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
        &'_ mut self,
        _input_ref: crate::input_data::InputRef<'data>,
        _file: &std::fs::File,
        _kind: crate::file_kind::FileKind,
    ) -> Result<Option<Box<LtoInputInfo<'data>>>> {
        unreachable!();
    }

    pub(crate) fn from_args<C: ElfClass>(
        _args: &'data ElfArgs,
        _linker_plugin_arena: &'data colosseum::sync::Arena<LoadedPlugin>,
        _herd: &'data bumpalo_herd::Herd,
    ) -> Result<Option<LinkerPlugin<'data>>> {
        Ok(None)
    }

    pub(crate) fn is_initialised(&self) -> bool {
        false
    }

    pub(crate) fn all_symbols_read<F: FileSystem, C: ElfClass>(
        &mut self,
        _symbol_db: &mut SymbolDb<'data, Elf<C>>,
        _resolver: &mut Resolver<'data, Elf<C>>,
        _file_loader: &mut FileLoader<'data, F>,
        _per_symbol_flags: &mut PerSymbolFlags,
        _output_sections: &mut OutputSections<'data, Elf<C>>,
        _layout_rules_builder: &mut LayoutRulesBuilder<'data>,
    ) -> Result {
        Ok(())
    }
}

pub(crate) struct LtoInput<'data> {
    _p: PhantomData<&'data ()>,
}

pub(crate) fn resolve_lto_symbols<'data, 'scope, C: ElfClass>(
    _obj: &LtoInput<'data>,
    _resources: &'scope crate::resolution::ResolutionResources<'data, 'scope, Elf<C>>,
    _definitions_out: &mut [SymbolId],
    _scope: &Scope<'scope>,
) -> Result {
    Ok(())
}
