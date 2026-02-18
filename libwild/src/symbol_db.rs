//! Reads global symbols for each input file and builds a map from symbol names to IDs together with
//! information about where each symbol can be obtained.

use crate::InputLinkerScript;
use crate::OutputKind;
use crate::args;
use crate::args::Args;
use crate::bail;
use crate::elf::RawSymbolName;
use crate::error;
use crate::error::Context as _;
use crate::error::Error;
use crate::error::Result;
use crate::export_list::ExportList;
use crate::grouping;
use crate::grouping::Group;
use crate::grouping::SequencedInput;
use crate::grouping::SequencedInputObject;
use crate::grouping::SequencedLinkerScript;
use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::hash::hash_bytes;
use crate::input_data::AuxiliaryFiles;
use crate::input_data::FileId;
use crate::input_data::LoadedInputs;
use crate::input_data::PRELUDE_FILE_ID;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::parsing;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::Prelude;
use crate::parsing::SymbolPlacement;
use crate::parsing::SyntheticSymbols;
use crate::platform;
use crate::platform::ObjectFile;
use crate::platform::RawSymbolName as _;
use crate::platform::Symbol;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::resolution::ResolvedSyntheticSymbols;
use crate::sharding::ShardKey;
use crate::symbol::PreHashedSymbolName;
use crate::symbol::UnversionedSymbolName;
use crate::symbol::VersionedSymbolName;
use crate::timing_phase;
use crate::value_flags::AtomicPerSymbolFlags;
use crate::value_flags::FlagsForSymbol;
use crate::value_flags::PerSymbolFlags;
use crate::value_flags::RawFlags;
use crate::value_flags::ValueFlags;
use crate::verbose_timing_phase;
use crate::version_script::RustVersionScript;
use crate::version_script::VersionScript;
use crossbeam_queue::SegQueue;
use hashbrown::HashMap;
use hashbrown::hash_map;
use itertools::Itertools;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::shf;
use rayon::iter::IndexedParallelIterator as _;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::IntoParallelRefMutIterator as _;
use rayon::iter::ParallelIterator;
use std::fmt::Display;
use std::mem::take;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use symbolic_demangle::demangle;

#[derive(Debug)]
pub struct SymbolDb<'data, O: ObjectFile<'data>> {
    pub(crate) args: &'data Args,

    pub(crate) groups: Vec<Group<'data, O>>,

    buckets: Vec<SymbolBucket<'data>>,

    /// Which file each symbol ID belongs to.
    symbol_file_ids: Vec<FileId>,

    /// Mapping from symbol IDs to the canonical definition of that symbol. For global symbols that
    /// were selected as the definition and for all locals, this will point to itself. e.g. the
    /// value at index 5 will be the symbol ID 5.
    symbol_definitions: Vec<SymbolId>,

    /// The names of symbols that mark the start / stop of sections. These are indexed by the
    /// offset into the SyntheticSymbols' symbol IDs.
    start_stop_symbol_names: Vec<UnversionedSymbolName<'data>>,

    pub(crate) version_script: VersionScript<'data>,
    pub(crate) export_list: Option<ExportList<'data>>,

    /// The name of the entry symbol if overridden by a linker script.
    entry: Option<&'data [u8]>,

    pub(crate) output_kind: OutputKind,
    pub(crate) herd: &'data bumpalo_herd::Herd,
}

/// Borrows from a SymbolDb, but allows temporary atomic access to some of the tables. These tables
/// are returned to the original SymbolDb when the AtomicSymbolDb is dropped. If the AtomicSymbolDb
/// gets leaked, then the tables in the original SymbolDb will remain empty. Provides some, but not
/// all of the APIs provided by SymbolDb.
struct AtomicSymbolDb<'data, 'db, O: ObjectFile<'data>> {
    db: &'db mut SymbolDb<'data, O>,
    definitions: Vec<AtomicSymbolId>,
}

#[derive(Debug)]
struct SymbolBucket<'data> {
    /// Mapping from global symbol names to a symbol ID with that name. If there are multiple
    /// globals with the same name, then this will point to the one we encountered first, which may
    /// not be the selected definition. In order to find the selected definition, you still need to
    /// look at `symbol_definitions`.
    name_to_id: PassThroughHashMap<UnversionedSymbolName<'data>, SymbolId>,

    versioned_name_to_id: PassThroughHashMap<VersionedSymbolName<'data>, SymbolId>,

    /// Global symbols that have multiple definitions keyed by the first symbol with that name.
    alternative_definitions: HashMap<SymbolId, Vec<SymbolId>>,

    /// Alternative definitions, but only for versioned symbols. This might be more efficient with
    /// a proper multi-map that doesn't need a separate Vec for each value, however we don't
    /// expect many entries here.
    alternative_versioned_definitions: HashMap<SymbolId, Vec<SymbolId>>,
}

/// A global symbol that hasn't been put into our database yet.
#[derive(Clone, Copy)]
struct PendingSymbol<'data> {
    symbol_id: SymbolId,
    name: PreHashed<UnversionedSymbolName<'data>>,
}

#[derive(Clone, Copy)]
struct PendingVersionedSymbol<'data> {
    symbol_id: SymbolId,
    name: PreHashed<VersionedSymbolName<'data>>,
}

/// An ID for a symbol. All symbols from all input files are allocated a unique symbol ID. The
/// symbol ID 0 is reserved for the undefined symbol.
#[derive(Clone, Copy, derive_more::Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[debug("sym-{_0}")]
pub(crate) struct SymbolId(u32);

struct AtomicSymbolId(AtomicU32);

/// A range of symbol IDs that are defined by the same input file.
///
/// This exists to translate between 3 different ways of identifying a symbol:
/// - A `SymbolId` is a globally unique identifier for a symbol.
/// - An `object::SymbolIndex` is an index into the ELF symbol table of the input file.
/// - A `usize` offset is an index into our own data structures for the file.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SymbolIdRange {
    start_symbol_id: SymbolId,
    num_symbols: usize,
}

pub(crate) struct SymbolNameDisplay<'data> {
    name: Option<UnversionedSymbolName<'data>>,
    demangle: bool,
}

impl SymbolIdRange {
    pub(crate) fn prelude(num_symbols: usize) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id: SymbolId::undefined(),
            num_symbols,
        }
    }

    pub(crate) fn input(start_symbol_id: SymbolId, num_symbols: usize) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id,
            num_symbols,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.num_symbols
    }

    pub(crate) fn start(&self) -> SymbolId {
        self.start_symbol_id
    }

    pub(crate) fn as_usize(&self) -> std::ops::Range<usize> {
        self.start_symbol_id.as_usize()..self.start_symbol_id.as_usize() + self.num_symbols
    }

    pub(crate) fn offset_to_id(&self, offset: usize) -> SymbolId {
        debug_assert!(offset < self.num_symbols);
        self.start_symbol_id.add_usize(offset)
    }

    pub(crate) fn id_to_offset(&self, symbol_id: SymbolId) -> usize {
        let offset = (symbol_id.0 - self.start_symbol_id.0) as usize;
        debug_assert!(
            offset < self.num_symbols,
            "{symbol_id} not within {}..{}",
            self.start_symbol_id.0,
            self.start_symbol_id.0 as usize + self.num_symbols
        );
        offset
    }

    pub(crate) fn offset_to_input(&self, offset: usize) -> object::SymbolIndex {
        debug_assert!(offset < self.num_symbols);
        object::SymbolIndex(offset)
    }

    pub(crate) fn input_to_offset(&self, symbol_index: object::SymbolIndex) -> usize {
        let offset = symbol_index.0;
        debug_assert!(offset < self.num_symbols);
        offset
    }

    pub(crate) fn input_to_id(&self, symbol_index: object::SymbolIndex) -> SymbolId {
        self.offset_to_id(self.input_to_offset(symbol_index))
    }

    pub(crate) fn id_to_input(&self, symbol_id: SymbolId) -> object::SymbolIndex {
        self.offset_to_input(self.id_to_offset(symbol_id))
    }

    /// Returns a range that covers from the start of `a` to the end of `b`.
    pub(crate) fn covering(a: SymbolIdRange, b: SymbolIdRange) -> SymbolIdRange {
        SymbolIdRange {
            start_symbol_id: a.start_symbol_id,
            num_symbols: b.start_symbol_id.as_usize() + b.len() - a.start_symbol_id.as_usize(),
        }
    }

    pub(crate) fn empty() -> SymbolIdRange {
        Self::input(SymbolId::from_usize(0), 0)
    }

    pub(crate) fn contains(&self, id: SymbolId) -> bool {
        self.start() <= id && id < self.start().add_usize(self.len())
    }
}

impl IntoIterator for SymbolIdRange {
    type Item = SymbolId;

    type IntoIter = SymbolIdRangeIterator;

    fn into_iter(self) -> Self::IntoIter {
        SymbolIdRangeIterator {
            remaining: self.len(),
            next: self.start_symbol_id,
        }
    }
}

pub(crate) struct SymbolIdRangeIterator {
    remaining: usize,
    next: SymbolId,
}

impl Iterator for SymbolIdRangeIterator {
    type Item = SymbolId;

    fn next(&mut self) -> Option<Self::Item> {
        self.remaining = self.remaining.checked_sub(1)?;
        let value = self.next;
        self.next = value.next();
        Some(value)
    }
}

struct SymbolLoadOutputs<'data> {
    /// Pending non-versioned symbols, grouped by hash bucket.
    pending_symbols_by_bucket: Vec<PendingSymbolHashBucket<'data>>,
}

#[derive(Default, Clone)]
struct PendingSymbolHashBucket<'data> {
    symbols: Vec<PendingSymbol<'data>>,

    versioned_symbols: Vec<PendingVersionedSymbol<'data>>,
}

impl<'data, O: ObjectFile<'data>> SymbolDb<'data, O> {
    /// If the version script is optimized fur rust, we downgraded all symbols to local visibility.
    /// This promotes symbols marked for global visibility in a Rust version script back to global.
    /// Also adds the non-interposable flag to all local symbols.
    pub(crate) fn handle_rust_version_script(
        &self,
        rust_vscript: &RustVersionScript<'data>,
        per_symbol_flags: &mut PerSymbolFlags,
    ) {
        verbose_timing_phase!("Upgrade locals for export");
        let atomic_per_symbol_flags = per_symbol_flags.borrow_atomic();

        rust_vscript.global.par_iter().for_each(|symbol| {
            let prehashed = UnversionedSymbolName::prehashed(symbol);
            if let Some(symbol_id) = self.get_unversioned(&prehashed) {
                atomic_per_symbol_flags
                    .get_atomic(self.definition(symbol_id))
                    .remove(ValueFlags::DOWNGRADE_TO_LOCAL);
            }
        });

        // Don't forget to add the non-interposable flag the local symbols.
        // We coudn't do this earlier as we didn't know which symbols would remain
        // local.
        per_symbol_flags
            .flags_mut()
            .par_iter_mut()
            .for_each(|flags| {
                let flags_val = flags.get();
                if flags_val.is_downgraded_to_local() {
                    *flags = (flags_val | ValueFlags::NON_INTERPOSABLE).raw();
                }
            });
    }

    pub(crate) fn new(
        args: &'data Args,
        output_kind: OutputKind,
        auxiliary: &AuxiliaryFiles<'data>,
        herd: &'data bumpalo_herd::Herd,
    ) -> Result<Self> {
        let version_script = auxiliary
            .version_script_data
            .map(VersionScript::parse)
            .transpose()?
            .unwrap_or_default();

        let export_list = auxiliary
            .export_list_data
            .map(ExportList::parse)
            .transpose()?;

        let num_buckets = num_symbol_hash_buckets(args);
        let mut buckets = Vec::new();
        buckets.resize_with(num_buckets, || SymbolBucket {
            name_to_id: Default::default(),
            versioned_name_to_id: Default::default(),
            alternative_definitions: HashMap::new(),
            alternative_versioned_definitions: HashMap::new(),
        });

        let mut symbol_db = SymbolDb {
            args,
            buckets,
            symbol_file_ids: Vec::new(),
            symbol_definitions: Vec::new(),
            groups: Vec::new(),
            start_stop_symbol_names: Default::default(),
            version_script,
            export_list,
            entry: None,
            output_kind,
            herd,
        };

        for symbol in &args.export_list {
            symbol_db
                .export_list
                .get_or_insert_default()
                .add_symbol(symbol, true)?;
        }

        Ok(symbol_db)
    }

    pub(crate) fn add_inputs(
        &mut self,
        per_symbol_flags: &mut PerSymbolFlags,
        output_sections: &mut OutputSections<'data>,
        layout_rules_builder: &mut LayoutRulesBuilder<'data>,
        loaded: LoadedInputs<'data, O>,
    ) -> Result {
        timing_phase!("Load inputs into symbol DB");

        let parsed_objects = loaded.objects.into_iter().try_collect()?;

        let processed_linker_scripts = parsing::process_linker_scripts(
            &loaded.linker_scripts,
            output_sections,
            layout_rules_builder,
        )?;

        self.add_version_script_from_linker_scripts(&loaded.linker_scripts)?;

        let pre_existing_groups = self.groups.len();

        if self.groups.is_empty() {
            self.groups
                .push(Group::Prelude(crate::parsing::Prelude::new(
                    self.args,
                    self.output_kind,
                )));
        }

        grouping::create_groups(self, parsed_objects, processed_linker_scripts);

        self.create_lto_input_groups(loaded.lto_objects)?;

        let new_groups = &self.groups[pre_existing_groups..];

        let num_symbols = new_groups.iter().map(|group| group.num_symbols()).sum();

        self.symbol_definitions.reserve(num_symbols);
        per_symbol_flags.reserve(num_symbols);
        self.symbol_file_ids.reserve(num_symbols);

        let mut writers = SymbolVecWriters::new(
            &mut self.symbol_definitions,
            &mut per_symbol_flags.flags,
            &mut self.symbol_file_ids,
        );

        let mut per_group_shards = new_groups
            .iter()
            .map(|group| writers.new_shard(group))
            .collect_vec();

        let per_group_outputs = read_symbols(
            &self.version_script,
            &mut per_group_shards,
            self.args,
            &self.export_list,
            self.output_kind,
        )?;

        populate_symbol_db(&mut self.buckets, &per_group_outputs);

        {
            verbose_timing_phase!("Return shards");

            for shard in per_group_shards {
                writers.return_shard(shard);
            }
        }

        rayon::join(
            || {
                // This can take a while, so do it in parallel with other work.
                verbose_timing_phase!("Drop per-group outputs");
                drop(per_group_outputs);
            },
            || {
                verbose_timing_phase!("Apply linker scripts");

                for script in &loaded.linker_scripts {
                    self.apply_linker_script(script);
                }
            },
        );

        Ok(())
    }

    #[cfg(feature = "plugins")]
    fn create_lto_input_groups(
        &mut self,
        lto_objects: Vec<Result<Box<crate::linker_plugins::LtoInputInfo<'data>>>>,
    ) -> Result {
        if lto_objects.is_empty() {
            return Ok(());
        }

        verbose_timing_phase!("Create LTO input groups");

        let lto_objects = lto_objects.into_iter().collect::<Result<Vec<_>>>()?;

        for group_objects in lto_objects
            .into_iter()
            .chunks(crate::input_data::MAX_FILES_PER_GROUP as usize)
            .into_iter()
        {
            let mut next_symbol_id = self.next_symbol_id();
            let group_index = self.next_group_index();

            self.groups.push(Group::LtoInputs(
                group_objects
                    .into_iter()
                    .enumerate()
                    .map(|(file_index, o)| {
                        let symbol_id_range = SymbolIdRange::input(next_symbol_id, o.num_symbols());
                        let input_obj = o.into_input_object(
                            FileId::new(group_index, file_index as u32),
                            symbol_id_range,
                        );
                        next_symbol_id = next_symbol_id.add_usize(symbol_id_range.len());
                        input_obj
                    })
                    .collect(),
            ));
        }

        Ok(())
    }

    #[cfg(not(feature = "plugins"))]
    #[allow(
        clippy::unused_self,
        clippy::needless_pass_by_value,
        clippy::needless_pass_by_ref_mut
    )]
    fn create_lto_input_groups(
        &mut self,
        lto_objects: Vec<Result<Box<crate::linker_plugins::LtoInputInfo<'data>>>>,
    ) -> Result {
        if !lto_objects.is_empty() {
            return Err(linker_plugin_disabled_error());
        }
        Ok(())
    }

    /// Adds a new synthetic symbol. `syn` must have been the most recently added group.
    pub(crate) fn add_synthetic_symbol(
        &mut self,
        per_symbol_flags: &mut PerSymbolFlags,
        symbol_name: PreHashed<UnversionedSymbolName<'data>>,
        syn: &ResolvedSyntheticSymbols<'data>,
    ) -> SymbolId {
        debug_assert_eq!(syn.file_id.group() + 1, self.groups.len());

        let symbol_id = SymbolId::from_usize(self.symbol_definitions.len());

        debug_assert_eq!(
            symbol_id.0,
            syn.start_symbol_id.0 + syn.symbol_definitions.len() as u32
        );

        let num_buckets = self.buckets.len();
        self.buckets[symbol_name.hash() as usize % num_buckets].add_symbol(&PendingSymbol {
            symbol_id,
            name: symbol_name,
        });

        self.symbol_definitions.push(symbol_id);
        self.start_stop_symbol_names.push(*symbol_name);
        let Group::SyntheticSymbols(s) = &mut self.groups[syn.file_id.group()] else {
            panic!("Tried to add synthetic symbol to non-synthetic-symbol group");
        };
        s.symbol_id_range.num_symbols += 1;
        self.symbol_file_ids.push(syn.file_id);

        per_symbol_flags.push(ValueFlags::NON_INTERPOSABLE);

        symbol_id
    }

    /// Applies overrides for symbols wrapped via the --wrap= argument. Note that like GNU ld, our
    /// wrapping mechanism only affects resolution of undefined symbols. Defined symbols will be
    /// unaffected. This means that references to a symbol from within the compilation unit that
    /// defines it will not go via the wrapper. This is in contrast to LLD where wrapping also
    /// affects references to symbols in compilation units where those symbols are defined. Our main
    /// reason for this choice of behaviour is that it's much simpler to implement.
    pub(crate) fn apply_wrapped_symbol_overrides(&mut self) {
        if self.args.wrap.is_empty() {
            return;
        }

        verbose_timing_phase!("Apply wrapped symbol overrides");

        let allocator = self.herd.get();

        for name in &self.args.wrap {
            let name_bytes = allocator.alloc_slice_copy(name.as_bytes());
            let orig_id = self.get_unversioned(&UnversionedSymbolName::prehashed(name_bytes));
            let wrap_name = format!("__wrap_{name}");
            if let Some(wrap_id) =
                self.get_unversioned(&UnversionedSymbolName::prehashed(wrap_name.as_bytes()))
            {
                self.override_name(UnversionedSymbolName::prehashed(name_bytes), wrap_id);
            }

            if let Some(orig_id) = orig_id {
                let real_name = allocator.alloc_slice_copy(format!("__real_{name}").as_bytes());
                self.override_name(UnversionedSymbolName::prehashed(real_name), orig_id);
            }
        }
    }

    /// Overrides `name` to point to `symbol_id`. Returns the old symbol ID for `name`.
    fn override_name(
        &mut self,
        name: PreHashed<UnversionedSymbolName<'data>>,
        symbol_id: SymbolId,
    ) -> Option<SymbolId> {
        let num_buckets = self.buckets.len();
        self.buckets[name.hash() as usize % num_buckets]
            .name_to_id
            .insert(name, symbol_id)
    }

    /// Reads the symbol visibility from the original object.
    pub(crate) fn input_symbol_visibility(&self, symbol_id: SymbolId) -> Visibility {
        let file_id = self.file_id_for_symbol(symbol_id);
        debug_assert!(self.file(file_id).symbol_id_range().contains(symbol_id));
        match &self.groups[file_id.group()] {
            Group::Prelude(_) => Visibility::Default,
            Group::Objects(parsed_input_objects) => {
                let obj = &parsed_input_objects[file_id.file()];
                let local_index = symbol_id.to_input(obj.symbol_id_range);

                let Ok(obj_symbol) = obj.parsed.object.symbol(local_index) else {
                    return Visibility::Default;
                };

                obj_symbol.visibility()
            }
            Group::LinkerScripts(_) => Visibility::Default,
            Group::SyntheticSymbols(_) => Visibility::Default,
            #[cfg(feature = "plugins")]
            Group::LtoInputs(lto_objects) => {
                lto_objects[file_id.file()].symbol_visibility(symbol_id)
            }
        }
    }

    /// Returns a struct that can be used to print debug information about the specified symbol.
    pub(crate) fn symbol_debug<'a>(
        &'a self,
        per_symbol_flags: &'a dyn FlagsForSymbol,
        symbol_id: SymbolId,
    ) -> SymbolDebug<'a, 'data, O> {
        SymbolDebug {
            db: self,
            symbol_id,
            per_symbol_flags,
        }
    }

    pub(crate) fn symbol_name_for_display(&self, symbol_id: SymbolId) -> SymbolNameDisplay<'data> {
        SymbolNameDisplay {
            name: self.symbol_name(symbol_id).ok(),
            demangle: self.args.demangle,
        }
    }

    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> Result<UnversionedSymbolName<'data>> {
        let file_id = self.file_id_for_symbol(symbol_id);
        match &self.groups[file_id.group()] {
            Group::Prelude(prelude) => Ok(prelude.symbol_name(symbol_id)),
            Group::Objects(parsed_input_objects) => {
                parsed_input_objects[file_id.file()].symbol_name(symbol_id)
            }
            Group::LinkerScripts(scripts) => Ok(scripts[file_id.file()].symbol_name(symbol_id)),
            Group::SyntheticSymbols(syn) => {
                Ok(self.start_stop_symbol_names[syn.symbol_id_range.id_to_offset(symbol_id)])
            }
            #[cfg(feature = "plugins")]
            Group::LtoInputs(lto_objects) => Ok(lto_objects[file_id.file()].symbol_name(symbol_id)),
        }
    }

    /// Get the version of a symbol. Only intended for diagnostic purposes.
    pub(crate) fn symbol_version_debug(&self, symbol_id: SymbolId) -> Option<String> {
        let file_id = self.file_id_for_symbol(symbol_id);
        match &self.groups[file_id.group()] {
            Group::Objects(parsed_input_objects) => {
                parsed_input_objects[file_id.file()].symbol_version_debug(symbol_id)
            }
            _ => None,
        }
    }

    pub(crate) fn flags_for_symbol(
        &self,
        per_symbol_flags: &PerSymbolFlags,
        symbol_id: SymbolId,
    ) -> ValueFlags {
        let mut flags = per_symbol_flags.flags_for_symbol(self.definition(symbol_id));
        flags.merge(per_symbol_flags.flags_for_symbol(symbol_id));
        flags
    }

    pub(crate) fn num_symbols(&self) -> usize {
        self.symbol_definitions.len()
    }

    pub(crate) fn num_regular_objects(&self) -> usize {
        self.groups
            .iter()
            .map(|group| match group {
                Group::Objects(objects) => objects.len(),
                _ => 0,
            })
            .sum()
    }

    pub(crate) fn num_lto_objects(&self) -> usize {
        self.groups
            .iter()
            .map(|group| match group {
                #[cfg(feature = "plugins")]
                Group::LtoInputs(objects) => objects.len(),
                _ => 0,
            })
            .sum()
    }

    /// If we have a symbol that when demangled produces `target_name`, then return the mangled
    /// name. Note, this scans every symbol, so should only be used for debugging / diagnostic
    /// purposes.
    pub(crate) fn find_mangled_name(&self, target_name: &str) -> Option<String> {
        for i in 1..self.num_symbols() {
            let symbol_id = SymbolId(i as u32);
            let Ok(name) = self.symbol_name(symbol_id) else {
                continue;
            };

            let Ok(name) = std::str::from_utf8(name.bytes()) else {
                continue;
            };

            if demangle(name) == target_name {
                return Some(name.to_owned());
            }
        }

        None
    }

    /// Returns our mapping from symbol IDs to the IDs that define them. Definitions should be
    /// restored later by calling `restore_definitions`. While the definitions are taken, any method
    /// that requires definitions will fail.
    pub(crate) fn take_definitions(&mut self) -> Vec<SymbolId> {
        take(&mut self.symbol_definitions)
    }

    pub(crate) fn restore_definitions(&mut self, definitions: Vec<SymbolId>) {
        self.symbol_definitions = definitions;
    }

    fn borrow_atomic<'db>(&'db mut self) -> AtomicSymbolDb<'data, 'db, O> {
        let definitions = self
            .take_definitions()
            .into_iter()
            .map(|id| id.as_atomic())
            .collect();

        AtomicSymbolDb {
            db: self,
            definitions,
        }
    }

    pub(crate) fn file_id_for_symbol(&self, symbol_id: SymbolId) -> FileId {
        self.symbol_file_ids[symbol_id.as_usize()]
    }

    /// Returns whether the supplied symbol ID is the canonical ID. A symbol won't be canonical, if
    /// it resolves to a different symbol. The symbol may still be undefined.
    pub(crate) fn is_canonical(&self, symbol_id: SymbolId) -> bool {
        let resolution = self.symbol_definitions[symbol_id.as_usize()];
        resolution == symbol_id
    }

    pub(crate) fn definition(&self, symbol_id: SymbolId) -> SymbolId {
        // We need to do two steps when finding the definition for a symbol, since the definition
        // may have changed since we did the original name lookup. It would be possible to avoid
        // this, by resolving all definitions before we resolve references, except then, due to
        // archive semantics, we'd need to do two passes to resolve symbols, one to determine which
        // archive members to load, then a second to determine which symbols to use.
        let step1 = self.symbol_definitions[symbol_id.as_usize()];
        self.symbol_definitions[step1.as_usize()]
    }

    pub(crate) fn replace_definition(&mut self, symbol_id: SymbolId, new_definition: SymbolId) {
        self.symbol_definitions[symbol_id.as_usize()] = new_definition;
    }

    pub(crate) fn file<'db>(&'db self, file_id: FileId) -> SequencedInput<'db, 'data, O> {
        match &self.groups[file_id.group()] {
            Group::Prelude(prelude) => SequencedInput::Prelude(prelude),
            Group::Objects(parsed_input_objects) => {
                SequencedInput::Object(&parsed_input_objects[file_id.file()])
            }
            Group::LinkerScripts(scripts) => SequencedInput::LinkerScript(&scripts[file_id.file()]),
            Group::SyntheticSymbols(syn) => SequencedInput::SyntheticSymbols(syn),
            #[cfg(feature = "plugins")]
            Group::LtoInputs(lto_objects) => SequencedInput::LtoInput(&lto_objects[file_id.file()]),
        }
    }

    pub(crate) fn is_mapping_symbol(&self, symbol_id: SymbolId) -> bool {
        let Ok(name) = self.symbol_name(symbol_id) else {
            // We don't want to bother the caller with an error here. If there's a problem getting
            // the name, it will be reported elsewhere.
            return false;
        };
        is_mapping_symbol_name(name.bytes())
    }

    pub(crate) fn get_unversioned(
        &self,
        prehashed: &PreHashed<UnversionedSymbolName>,
    ) -> Option<SymbolId> {
        let num_buckets = self.buckets.len();
        self.buckets[prehashed.hash() as usize % num_buckets]
            .name_to_id
            .get(prehashed)
            .copied()
    }

    #[inline(always)]
    pub(crate) fn get(&self, key: &PreHashedSymbolName, allow_dynamic: bool) -> Option<SymbolId> {
        let num_buckets = self.buckets.len();

        match key {
            PreHashedSymbolName::Unversioned(key) => {
                let bucket = &self.buckets[key.hash() as usize % num_buckets];
                let symbol_id = bucket.name_to_id.get(key).copied()?;

                if !allow_dynamic && self.file(self.file_id_for_symbol(symbol_id)).is_dynamic() {
                    return bucket.get_non_dynamic(symbol_id, self);
                }

                Some(symbol_id)
            }
            PreHashedSymbolName::Versioned(key) => {
                let bucket = &self.buckets[key.hash() as usize % num_buckets];
                let symbol_id = bucket.versioned_name_to_id.get(key).copied()?;

                if !allow_dynamic && self.file(self.file_id_for_symbol(symbol_id)).is_dynamic() {
                    return bucket.get_non_dynamic(symbol_id, self);
                }

                Some(symbol_id)
            }
        }
    }

    pub(crate) fn all_unversioned_symbols(
        &self,
    ) -> impl Iterator<Item = (&PreHashed<UnversionedSymbolName<'data>>, &SymbolId)> {
        self.buckets.iter().flat_map(|b| b.name_to_id.iter())
    }

    #[inline(always)]
    pub(crate) fn symbol_strength(
        &self,
        symbol_id: SymbolId,
        resolved: &[ResolvedGroup],
    ) -> SymbolStrength {
        let file_id = self.file_id_for_symbol(symbol_id);
        match &resolved[file_id.group()].files[file_id.file()] {
            ResolvedFile::Object(obj) => obj.common.symbol_strength(symbol_id),
            ResolvedFile::Dynamic(obj) => obj.common.symbol_strength(symbol_id),
            #[cfg(feature = "plugins")]
            ResolvedFile::LtoInput(obj) => {
                use crate::linker_plugins::SymbolKind;

                let SequencedInput::LtoInput(obj) = self.file(obj.file_id) else {
                    unreachable!();
                };
                if !obj.enabled {
                    return SymbolStrength::Undefined;
                }
                let local_index = symbol_id.to_input(obj.symbol_id_range);
                let obj_symbol = &obj.symbols[local_index.0];
                match obj_symbol.kind {
                    Some(SymbolKind::Def) => SymbolStrength::Strong,
                    Some(SymbolKind::WeakDef) => SymbolStrength::Weak,
                    Some(SymbolKind::Common) => SymbolStrength::Common(obj_symbol.size),
                    _ => SymbolStrength::Undefined,
                }
            }
            _ => SymbolStrength::Undefined,
        }
    }

    /// Returns whether the specified symbol is defined in a section with the SHF_GROUP flag set.
    fn is_in_comdat_group(&self, symbol_id: SymbolId, resolved: &[ResolvedGroup]) -> bool {
        let file_id = self.file_id_for_symbol(symbol_id);
        let ResolvedFile::Object(obj) = &resolved[file_id.group()].files[file_id.file()] else {
            return false;
        };

        let local_index = symbol_id.to_input(obj.common.symbol_id_range);
        let Ok(obj_symbol) = obj.common.object.symbol(local_index) else {
            return false;
        };

        let section_index = obj_symbol.section_index();
        let Ok(header) = obj.common.object.section(section_index) else {
            return false;
        };

        let flags = SectionFlags::from_header(header);

        flags.contains(shf::GROUP)
    }

    pub(crate) fn entry_symbol_name(&self) -> &[u8] {
        // The --entry flag is used first, falling back to what the linker script says, or otherwise
        // defaults to `_start`.
        self.args
            .entry
            .as_ref()
            .map(|n| n.as_bytes())
            .or(self.entry)
            .unwrap_or(b"_start")
    }

    pub(crate) fn defsym_defined_via_cli_option(&self, symbol_name: &[u8]) -> bool {
        self.args
            .defsym
            .iter()
            .any(|(name, _)| name.as_bytes() == symbol_name)
    }

    pub(crate) fn missing_defsym_target_error(
        &self,
        symbol_name: &[u8],
        target_name: &str,
    ) -> Error {
        if self.defsym_defined_via_cli_option(symbol_name) {
            crate::error!(
                "Symbol '{}' referenced by --defsym does not exist",
                target_name
            )
        } else {
            crate::error!(
                "Undefined symbol '{}' referenced in expression",
                target_name
            )
        }
    }

    fn apply_linker_script(&mut self, script: &InputLinkerScript<'data>) {
        for cmd in &script.script.commands {
            if let crate::linker_script::Command::Entry(symbol_name) = cmd {
                self.entry = Some(*symbol_name);
            }
        }
    }

    pub(crate) fn next_symbol_id(&self) -> SymbolId {
        self.groups.last().map_or(SymbolId::undefined(), |group| {
            let range = group.symbol_id_range();
            range.start().add_usize(range.len())
        })
    }

    pub(crate) fn new_synthetic_symbols_group(&mut self) -> ResolvedSyntheticSymbols<'data> {
        let file_id = FileId::new(self.groups.len() as u32, 0);
        let start_symbol_id = self.next_symbol_id();

        self.groups.push(Group::SyntheticSymbols(SyntheticSymbols {
            file_id,
            symbol_id_range: SymbolIdRange::input(start_symbol_id, 0),
        }));

        ResolvedSyntheticSymbols {
            file_id,
            start_symbol_id,
            symbol_definitions: Vec::new(),
        }
    }

    fn add_version_script_from_linker_scripts(
        &mut self,
        linker_scripts: &[InputLinkerScript<'data>],
    ) -> Result {
        for script in linker_scripts {
            // Check if the linker script contains a VERSION command
            if let Some(version_content) = script.script.get_version_script_content() {
                if self.version_script != VersionScript::default() {
                    bail!("Multiple version scripts provided");
                }

                self.version_script = VersionScript::parse(crate::input_data::ScriptData {
                    raw: version_content,
                })?;
            }
        }

        Ok(())
    }

    pub(crate) fn groups_reserve(&mut self, additional: usize) {
        self.groups.reserve(additional);
    }

    pub(crate) fn next_group_index(&self) -> u32 {
        self.groups.len() as u32
    }

    pub(crate) fn add_group(&mut self, group: Group<'data, O>) {
        self.groups.push(group);
    }

    #[cfg(feature = "plugins")]
    pub(crate) fn disable_lto_inputs(&mut self) {
        for group in &mut self.groups {
            if let Group::LtoInputs(objects) = group {
                for obj in objects {
                    obj.enabled = false;
                }
            }
        }
    }
}

pub(crate) fn linker_plugin_disabled_error() -> Error {
    error!("Wild was compiled without linker-plugin support, but LTO inputs were detected")
}

struct SymbolVecWriters<'out> {
    symbol_definitions_writer: sharded_vec_writer::VecWriter<'out, SymbolId>,
    per_symbol_flags_writer: sharded_vec_writer::VecWriter<'out, RawFlags>,
    symbol_file_ids_writer: sharded_vec_writer::VecWriter<'out, FileId>,
}

impl<'out> SymbolVecWriters<'out> {
    fn new(
        symbol_definitions: &'out mut Vec<SymbolId>,
        per_symbol_flags: &'out mut Vec<RawFlags>,
        symbol_file_ids: &'out mut Vec<FileId>,
    ) -> Self {
        Self {
            symbol_definitions_writer: sharded_vec_writer::VecWriter::new(symbol_definitions),
            per_symbol_flags_writer: sharded_vec_writer::VecWriter::new(per_symbol_flags),
            symbol_file_ids_writer: sharded_vec_writer::VecWriter::new(symbol_file_ids),
        }
    }

    fn new_shard<'group, 'data, O: ObjectFile<'data>>(
        &mut self,
        group: &'group Group<'data, O>,
    ) -> SymbolWriterShard<'out, 'group, 'data, O> {
        let num_symbols = group.num_symbols();
        SymbolWriterShard {
            group,
            next: group.start_symbol_id(),
            resolutions: self.symbol_definitions_writer.take_shard(num_symbols),
            flags: self.per_symbol_flags_writer.take_shard(num_symbols),
            file_ids: self.symbol_file_ids_writer.take_shard(num_symbols),
        }
    }

    fn return_shard<'data, O: ObjectFile<'data>>(
        &mut self,
        shard: SymbolWriterShard<'_, '_, 'data, O>,
    ) {
        self.symbol_definitions_writer
            .return_shard(shard.resolutions);
        self.per_symbol_flags_writer.return_shard(shard.flags);
        self.symbol_file_ids_writer.return_shard(shard.file_ids);
    }
}

impl<'data> SymbolBucket<'data> {
    fn add_symbol(&mut self, pending: &PendingSymbol<'data>) {
        match self.name_to_id.entry(pending.name) {
            hash_map::Entry::Occupied(entry) => {
                let first_symbol_id = *entry.get();
                self.add_extra_symbol_definition(first_symbol_id, pending.symbol_id);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(pending.symbol_id);
            }
        }
    }

    fn add_versioned_symbol(&mut self, pending: &PendingVersionedSymbol<'data>) {
        match self.versioned_name_to_id.entry(pending.name) {
            hash_map::Entry::Occupied(entry) => {
                let first_symbol_id = *entry.get();
                self.alternative_versioned_definitions
                    .entry(first_symbol_id)
                    .or_default()
                    .push(pending.symbol_id);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(pending.symbol_id);
            }
        }
    }

    fn add_extra_symbol_definition(&mut self, first_symbol_id: SymbolId, new_symbol_id: SymbolId) {
        self.alternative_definitions
            .entry(first_symbol_id)
            .or_default()
            .push(new_symbol_id);
    }

    /// Returns the selected non-dynamic alternative to the supplied symbol, if any.
    fn get_non_dynamic<O: ObjectFile<'data>>(
        &self,
        symbol_id: SymbolId,
        symbol_db: &SymbolDb<'data, O>,
    ) -> Option<SymbolId> {
        self.alternative_definitions
            .get(&symbol_id)?
            .iter()
            .find(|alt| {
                // For now, we just get the first definition that isn't from a shared object. We
                // should actually take symbol binding into account, but don't yet.
                // TODO: Fix this.
                let file_id = symbol_db.file_id_for_symbol(**alt);
                !symbol_db.file(file_id).is_dynamic()
            })
            .copied()
    }
}

/// For each symbol that has multiple definitions, some of which may be weak, some strong, some
/// "common" symbols and some in archive entries that weren't loaded, resolve which version of the
/// symbol we're using. The symbol we select will be the first strongly defined symbol in a loaded
/// object, or if there are no strong definitions, then the first definition in a loaded object. If
/// a symbol definition is a common symbol, then the largest definition will be used.
pub(crate) fn resolve_alternative_symbol_definitions<'data, O: ObjectFile<'data>>(
    symbol_db: &mut SymbolDb<'data, O>,
    per_symbol_flags: &mut PerSymbolFlags,
    resolved: &[ResolvedGroup],
) -> Result {
    timing_phase!("Resolve alternative symbol definitions");

    let mut buckets = take(&mut symbol_db.buckets);
    let atomic_symbol_db = symbol_db.borrow_atomic();
    let atomic_per_symbol_flags = per_symbol_flags.borrow_atomic();
    let error_queue = SegQueue::new();

    buckets.par_iter_mut().for_each(|bucket| {
        verbose_timing_phase!("Resolve alternative for bucket");

        process_alternatives(
            &mut bucket.alternative_definitions,
            &error_queue,
            &atomic_symbol_db,
            &atomic_per_symbol_flags,
            resolved,
        );

        process_alternatives(
            &mut bucket.alternative_versioned_definitions,
            &error_queue,
            &atomic_symbol_db,
            &atomic_per_symbol_flags,
            resolved,
        );
    });

    drop(atomic_symbol_db);

    let mut duplicate_errors: Vec<Error> = error_queue.into_iter().collect();
    duplicate_errors.sort_by_key(|e| e.to_string());

    if !duplicate_errors.is_empty() {
        let error_details = duplicate_errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("\n");

        bail!("Duplicate symbols detected: {error_details}");
    }

    symbol_db.buckets = buckets;

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Visibility {
    Default,
    Protected,
    Hidden,
}

impl Visibility {
    pub(crate) fn from_elf_st_visibility(st_visibility: u8) -> Visibility {
        match st_visibility {
            object::elf::STV_PROTECTED => Visibility::Protected,
            object::elf::STV_HIDDEN => Visibility::Hidden,
            _ => Visibility::Default,
        }
    }
}

fn process_alternatives<'data, O: ObjectFile<'data>>(
    alternative_definitions: &mut HashMap<SymbolId, Vec<SymbolId>>,
    error_queue: &SegQueue<Error>,
    symbol_db: &AtomicSymbolDb<'data, '_, O>,
    per_symbol_flags: &AtomicPerSymbolFlags,
    resolved: &[ResolvedGroup],
) {
    for (first, alternatives) in std::mem::take(alternative_definitions) {
        // Compute the most restrictive visibility of any of the alternative definitions. This is
        // the visibility we'll use for our selected symbol. This seems like odd behaviour, but it
        // matches what GNU ld appears to do and some programs will fail to link if we don't do
        // this.
        let visibility = alternatives
            .iter()
            .fold(symbol_db.input_symbol_visibility(first), |vis, id| {
                vis.max(symbol_db.input_symbol_visibility(*id))
            });

        match select_symbol(symbol_db, per_symbol_flags, first, &alternatives, resolved) {
            Ok(selected) => {
                symbol_db.update_definition(first, selected);

                for &alt in &alternatives {
                    symbol_db.update_definition(alt, selected);
                }

                if visibility != Visibility::Default {
                    handle_non_default_visibility(per_symbol_flags, first);

                    for alt in alternatives {
                        handle_non_default_visibility(per_symbol_flags, alt);
                    }
                }
            }
            Err(err) => {
                error_queue.push(err);
            }
        }
    }
}

/// Update value flags for `symbol_id` given that we've now changed its visibility to something
/// other than default.
fn handle_non_default_visibility(per_symbol_flags: &AtomicPerSymbolFlags, symbol_id: SymbolId) {
    // TODO: Currently we only make the symbol non-interposable, but we should also actually
    // change its visibility too. We need somewhere to store this information. We also need
    // linker-diff to report when we get exported dynamic symbols wrong.
    let flags = per_symbol_flags.get_atomic(symbol_id);
    if !flags.get().contains(ValueFlags::DYNAMIC) {
        flags.or_assign(ValueFlags::NON_INTERPOSABLE);
    }
}

/// Selects which version of the symbol to use. For more information on symbol priority, see
/// https://maskray.me/blog/2021-06-20-linker-symbol-resolution
#[inline(always)]
fn select_symbol<'data, O: ObjectFile<'data>>(
    symbol_db: &AtomicSymbolDb<'data, '_, O>,
    per_symbol_flags: &AtomicPerSymbolFlags,
    first_id: SymbolId,
    alternatives: &[SymbolId],
    resolved: &[ResolvedGroup],
) -> Result<SymbolId> {
    let mut max_common = None;
    let mut strong_symbol = None;
    let mut first_weak = None;

    for id in std::iter::once(first_id).chain(alternatives.iter().copied()) {
        let flags = per_symbol_flags.flags_for_symbol(id);

        // Dynamic symbols, even strong ones, don't override non-dynamic weak symbols, so in this
        // first pass, we ignore dynamic symbols.
        if flags.is_dynamic() {
            continue;
        }

        let strength = symbol_db.symbol_strength(id, resolved);
        match strength {
            SymbolStrength::Strong => {
                if let Some(existing) = strong_symbol {
                    // We don't implement full COMDAT logic, however if we encounter duplicate
                    // strong definitions, then we don't emit errors if all the strong definitions
                    // are defined in COMDAT group sections.
                    if (!symbol_db.is_in_comdat_group(existing, resolved)
                        || !symbol_db.is_in_comdat_group(id, resolved))
                        && !symbol_db.db.args.allow_multiple_definitions
                    {
                        bail!(
                            "{}, defined in {} and {}",
                            symbol_db.symbol_name_for_display(first_id),
                            symbol_db.file(symbol_db.file_id_for_symbol(existing)),
                            symbol_db.file(symbol_db.file_id_for_symbol(id)),
                        );
                    }
                } else {
                    strong_symbol = Some(id);
                }
            }
            SymbolStrength::Weak | SymbolStrength::GnuUnique => {
                if first_weak.is_none() {
                    first_weak = Some(id);
                }
            }
            SymbolStrength::Common(size) => {
                if let Some((previous_size, _)) = max_common
                    && size <= previous_size
                {
                    continue;
                }
                max_common = Some((size, id));
            }
            SymbolStrength::Undefined => {}
        }
    }

    if let Some(strong_symbol) = strong_symbol {
        return Ok(strong_symbol);
    }

    if let Some((_, alt)) = max_common {
        return Ok(alt);
    }

    if let Some(id) = first_weak {
        return Ok(id);
    }

    // If we've made it this far, then the symbol is only defined in shared objects. Pick the first
    // definition. Note, we don't check for duplicate strong definitions here because it's OK for
    // multiple shared objects to define the same symbol strongly.
    for alt in std::iter::once(first_id).chain(alternatives.iter().copied()) {
        let strength = symbol_db.symbol_strength(alt, resolved);
        if strength != SymbolStrength::Undefined {
            return Ok(alt);
        }
    }

    Ok(first_id)
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub(crate) enum SymbolStrength {
    /// The object containing this symbol wasn't loaded, so the definition can be ignored.
    Undefined,

    /// The object weakly defines the symbol.
    Weak,

    /// The object uses STB_GNU_UNIQUE binding.
    GnuUnique,

    /// The object strongly defines the symbol.
    Strong,

    /// The symbol is a "common" symbol with the specified size. The definition with the largest
    /// size will be selected.
    Common(u64),
}

/// Returns whether the supplied symbol name is for a [mapping
/// symbol](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#mapping-symbols).
pub(crate) fn is_mapping_symbol_name(name: &[u8]) -> bool {
    name.starts_with(b"$x") || name.starts_with(b"$d") || name == b"L0\x01"
}

fn read_symbols<'data, O: ObjectFile<'data>>(
    version_script: &VersionScript,
    shards: &mut [SymbolWriterShard<'_, '_, 'data, O>],
    args: &Args,
    export_list: &Option<ExportList<'data>>,
    output_kind: OutputKind,
) -> Result<Vec<SymbolLoadOutputs<'data>>> {
    timing_phase!("Read symbols");

    let num_buckets = num_symbol_hash_buckets(args);

    shards
        .par_iter_mut()
        .map(|shard| {
            read_symbols_for_group(
                shard,
                version_script,
                export_list,
                num_buckets,
                args,
                output_kind,
            )
        })
        .collect::<Result<Vec<SymbolLoadOutputs>>>()
}

fn read_symbols_for_group<'data, O: ObjectFile<'data>>(
    shard: &mut SymbolWriterShard<'_, '_, 'data, O>,
    version_script: &VersionScript,
    export_list: &Option<ExportList<'data>>,
    num_buckets: usize,
    args: &Args,
    output_kind: OutputKind,
) -> Result<SymbolLoadOutputs<'data>> {
    verbose_timing_phase!(
        "Read group symbols",
        group_id = shard.group.group_id(),
        num_symbols = shard.group.num_symbols()
    );

    let mut outputs = SymbolLoadOutputs {
        pending_symbols_by_bucket: vec![PendingSymbolHashBucket::default(); num_buckets],
    };

    match shard.group {
        Group::Prelude(prelude) => {
            prelude.load_symbols(shard, &mut outputs);
        }
        Group::Objects(parsed_input_objects) => {
            for obj in *parsed_input_objects {
                load_symbols_from_file(
                    obj,
                    version_script,
                    shard,
                    &mut outputs,
                    args,
                    export_list,
                    output_kind,
                )
                .with_context(|| format!("Failed to load symbols from `{}`", obj.parsed.input))?;
            }
        }
        Group::LinkerScripts(scripts) => {
            for script in scripts {
                load_linker_script_symbols(script, shard, &mut outputs);
            }
        }
        Group::SyntheticSymbols(_) => {
            // Custom section start/stop symbols are generated after archive handling.
        }
        #[cfg(feature = "plugins")]
        Group::LtoInputs(lto_objects) => {
            for obj in lto_objects {
                load_lto_symbols(shard, &mut outputs, obj);
            }
        }
    }

    Ok(outputs)
}

#[cfg(feature = "plugins")]
fn load_lto_symbols<'data, O: ObjectFile<'data>>(
    symbols_out: &mut SymbolWriterShard<'_, '_, 'data, O>,
    outputs: &mut SymbolLoadOutputs<'data>,
    obj: &crate::linker_plugins::LtoInput<'data>,
) {
    for (symbol_id, sym) in obj.symbols_iter() {
        if sym.is_definition() {
            if let Some(version) = sym.version {
                outputs.add_versioned(PendingVersionedSymbol::from_prehashed(
                    symbol_id,
                    UnversionedSymbolName::prehashed(sym.name.bytes()),
                    version,
                ));
            } else {
                outputs.add_non_versioned(PendingSymbol::new(symbol_id, sym.name.bytes()));
            }
            symbols_out.set_next(ValueFlags::empty(), symbol_id, obj.file_id);
        } else {
            symbols_out.set_next(ValueFlags::empty(), SymbolId::undefined(), obj.file_id);
        }
    }
}

fn populate_symbol_db<'data>(
    buckets: &mut [SymbolBucket<'data>],
    per_group_outputs: &[SymbolLoadOutputs<'data>],
) {
    timing_phase!("Populate symbol map");

    buckets.par_iter_mut().enumerate().for_each(|(b, bucket)| {
        verbose_timing_phase!("Process symbol bucket");

        // The following approximation should be an upper bound on the number of global
        // names we'll have. There will likely be at least a few global symbols with the
        // same name, in which case the actual number will be slightly smaller.
        let approx_num_symbols = per_group_outputs
            .iter()
            .map(|s| s.pending_symbols_by_bucket[b].symbols.len())
            .sum();
        bucket.name_to_id.reserve(approx_num_symbols);

        for outputs in per_group_outputs {
            let pending = &outputs.pending_symbols_by_bucket[b];

            for symbol in &pending.symbols {
                bucket.add_symbol(symbol);
            }

            for symbol in &pending.versioned_symbols {
                bucket.add_versioned_symbol(symbol);
            }
        }
    });
}

fn load_linker_script_symbols<'data, O: ObjectFile<'data>>(
    script: &SequencedLinkerScript<'data>,
    symbols_out: &mut SymbolWriterShard<'_, '_, 'data, O>,
    outputs: &mut SymbolLoadOutputs<'data>,
) {
    for (offset, definition) in script.parsed.symbol_defs.iter().enumerate() {
        let symbol_id = script.symbol_id_range.offset_to_id(offset);

        outputs.add_non_versioned(PendingSymbol::from_prehashed(
            symbol_id,
            PreHashed::new(
                UnversionedSymbolName::new(definition.name),
                hash_bytes(definition.name),
            ),
        ));

        let mut flags = ValueFlags::NON_INTERPOSABLE;
        // PROVIDE_HIDDEN symbols have hidden visibility, which means they should be
        // non-interposable (already set) and not exported to dynamic symbol table.
        if definition.is_hidden {
            flags |= ValueFlags::DOWNGRADE_TO_LOCAL;
        }
        symbols_out.set_next(flags, symbol_id, script.file_id);
    }
}

fn load_symbols_from_file<'data, O: ObjectFile<'data>>(
    s: &SequencedInputObject<'data, O>,
    version_script: &VersionScript,
    symbols_out: &mut SymbolWriterShard<'_, '_, 'data, O>,
    outputs: &mut SymbolLoadOutputs<'data>,
    args: &Args,
    export_list: &Option<ExportList<'data>>,
    output_kind: OutputKind,
) -> Result {
    if s.is_dynamic() {
        DynamicObjectSymbolLoader::new(&s.parsed.object)?.load_symbols(
            s.file_id,
            symbols_out,
            outputs,
        )
    } else {
        RegularObjectSymbolLoader {
            object: &s.parsed.object,
            args,
            version_script,
            archive_semantics: s.parsed.input.has_archive_semantics(),
            lib_name: s.parsed.input.lib_name(),
            export_list,
            output_kind,
        }
        .load_symbols(s.file_id, symbols_out, outputs)
    }
}

struct SymbolWriterShard<'out, 'group, 'data, O: ObjectFile<'data>> {
    group: &'group Group<'data, O>,
    resolutions: sharded_vec_writer::Shard<'out, SymbolId>,
    flags: sharded_vec_writer::Shard<'out, RawFlags>,
    file_ids: sharded_vec_writer::Shard<'out, FileId>,
    next: SymbolId,
}

impl<'out, 'group, 'data, O: ObjectFile<'data>> SymbolWriterShard<'out, 'group, 'data, O> {
    fn set_next(&mut self, flags: ValueFlags, resolution: SymbolId, file_id: FileId) {
        self.flags.push(flags.raw());
        self.resolutions.push(resolution);
        self.file_ids.push(file_id);
        self.next = SymbolId::from_usize(self.next.as_usize() + 1);
    }
}

trait SymbolLoader<'data, O: ObjectFile<'data>> {
    fn load_symbols(
        &self,
        file_id: FileId,
        symbols_out: &mut SymbolWriterShard<'_, '_, 'data, O>,
        outputs: &mut SymbolLoadOutputs<'data>,
    ) -> Result {
        let base_symbol_id = symbols_out.next;

        for symbol in self.object().symbols_iter() {
            let symbol_id = symbols_out.next;
            let mut flags = self.compute_value_flags(symbol);

            if symbol.is_undefined() || self.should_ignore_symbol(symbol) {
                symbols_out.set_next(flags, SymbolId::undefined(), file_id);
                continue;
            }

            let resolution = symbol_id;

            let local_index = symbol_id.offset_from(base_symbol_id);

            if symbol.is_local() {
                symbols_out.set_next(flags, resolution, file_id);
                continue;
            }

            let info = self.get_symbol_name_and_version(symbol, local_index)?;

            let name = UnversionedSymbolName::prehashed(info.name());

            if self.should_downgrade_to_local(&name) {
                flags |= ValueFlags::DOWNGRADE_TO_LOCAL;
                // If we're downgrading to a local, then we're writing a shared object. Shared
                // objects should never bypass the GOT for TLS variables. However, if we're
                // downgrading all symbols by default, that'd add the flag to all symbols, so we
                // have to do this later.
                if !self.downgrades_all() && !symbol.is_tls() {
                    flags |= ValueFlags::NON_INTERPOSABLE;
                }
            }

            if info.is_default() {
                let pending = PendingSymbol::from_prehashed(symbol_id, name);
                outputs.add_non_versioned(pending);
            }

            if let Some(version) = info.version_name() {
                let pending = PendingVersionedSymbol::from_prehashed(symbol_id, name, version);
                outputs.add_versioned(pending);
            }

            symbols_out.set_next(flags, resolution, file_id);
        }

        Ok(())
    }

    fn object(&self) -> &O;

    fn compute_value_flags(&self, symbol: &O::Symbol) -> ValueFlags;

    /// Returns whether we should downgrade a symbol with the specified name to be a local.
    fn should_downgrade_to_local(&self, _name: &PreHashed<UnversionedSymbolName>) -> bool {
        false
    }

    /// Returns whether we will downgrade all symbols by default and later upgrade some to global.
    fn downgrades_all(&self) -> bool {
        false
    }

    /// Returns whether the supplied symbol should be ignore.
    fn should_ignore_symbol(&self, _symbol: &O::Symbol) -> bool {
        false
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &O::Symbol,
        local_index: usize,
    ) -> Result<O::RawSymbolName>;
}

struct RegularObjectSymbolLoader<'a, 'data, O: ObjectFile<'data>> {
    object: &'a O,
    args: &'a Args,
    version_script: &'a VersionScript<'a>,
    archive_semantics: bool,
    lib_name: &'data [u8],
    export_list: &'a Option<ExportList<'a>>,
    output_kind: OutputKind,
}

struct DynamicObjectSymbolLoader<'a, 'data, O: ObjectFile<'data>> {
    object: &'a O,
    version_names: O::VersionNames,
}

impl<'a, 'data, O: ObjectFile<'data>> DynamicObjectSymbolLoader<'a, 'data, O> {
    fn new(object: &'a O) -> Result<Self> {
        let version_names = object.get_version_names()?;
        Ok(Self {
            object,
            version_names,
        })
    }
}

impl<'data, O: ObjectFile<'data>> SymbolLoader<'data, O>
    for RegularObjectSymbolLoader<'_, 'data, O>
{
    fn compute_value_flags(&self, sym: &O::Symbol) -> ValueFlags {
        let is_undefined = sym.is_undefined();

        let symbol_is_exported = || {
            if let Some(export_list) = &self.export_list
                && let Ok(symbol_name) = self.object.symbol_name(sym)
                && !&export_list.contains(&UnversionedSymbolName::prehashed(symbol_name))
            {
                return false;
            }
            true
        };
        let non_interposable = !sym.is_interposable()
            || sym.is_local()
            || self.output_kind.is_static_executable()
            // Symbols defined in an executable cannot be interposed since the executable is always the
            // first place checked for a symbol by the dynamic loader.
            || (!is_undefined && (
                self.output_kind.is_executable()
                || (self.archive_semantics && self.args.exclude_libs.should_exclude(self.lib_name))
                || (
                    self.args.b_symbolic == args::BSymbolicKind::All
                    // `-Bsymbolic-functions`
                    || (
                        self.args.b_symbolic == args::BSymbolicKind::Functions
                        && sym.is_func()
                    )
                    // `-Bsymbolic-non-weak`
                    || (
                        self.args.b_symbolic == args::BSymbolicKind::NonWeak
                        && !sym.is_weak()
                    )
                    // `-Bsymbolic-non-weak-functions`
                    || (
                        self.args.b_symbolic == args::BSymbolicKind::NonWeakFunctions
                        && (sym.is_func()
                        && !sym.is_weak())
                    )
                )
                // Bsymbolic does not affect symbols that are exported
                && !(self.export_list.is_some() && symbol_is_exported())
            ));

        let mut flags: ValueFlags = if sym.is_absolute() {
            ValueFlags::ABSOLUTE
        } else if sym.is_ifunc() {
            ValueFlags::IFUNC
        } else if is_undefined {
            // For undefined symbols, we tweak some of the flags later on in
            // `canonicalise_undefined_symbols`. We can't make those decisions now because we don't
            // know whether the symbol will remain undefined.
            ValueFlags::ABSOLUTE
        } else {
            ValueFlags::empty()
        };

        if non_interposable {
            flags |= ValueFlags::NON_INTERPOSABLE;
        }
        flags
    }

    fn should_downgrade_to_local(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        match self.version_script {
            // We first downgrade all symbols when using a Rust version script.
            // We're gonna set the ones that are exported back to global later.
            VersionScript::Rust(_) => true,
            VersionScript::Regular(version_script) => version_script.is_local(name),
        }
    }

    fn downgrades_all(&self) -> bool {
        matches!(self.version_script, VersionScript::Rust(_))
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &O::Symbol,
        _local_index: usize,
    ) -> Result<O::RawSymbolName> {
        Ok(<O::RawSymbolName as platform::RawSymbolName>::parse(
            self.object.symbol_name(symbol)?,
        ))
    }

    fn object(&self) -> &O {
        self.object
    }
}

impl<'data, O: ObjectFile<'data>> SymbolLoader<'data, O>
    for DynamicObjectSymbolLoader<'_, 'data, O>
{
    fn compute_value_flags(&self, symbol: &O::Symbol) -> ValueFlags {
        let mut flags = ValueFlags::DYNAMIC;
        if symbol.is_func() || symbol.is_ifunc() {
            flags |= ValueFlags::FUNCTION;
        }
        if symbol.is_undefined() {
            flags |= ValueFlags::ABSOLUTE;
        }
        flags
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &O::Symbol,
        local_index: usize,
    ) -> Result<O::RawSymbolName> {
        self.object
            .get_symbol_name_and_version(symbol, local_index, &self.version_names)
    }

    fn object(&self) -> &O {
        self.object
    }

    fn should_ignore_symbol(&self, symbol: &O::Symbol) -> bool {
        // Shared objects shouldn't export hidden symbols. If for some reason they do, ignore them.
        symbol.is_hidden()
    }
}

#[derive(Clone, Copy)]
pub(crate) struct SymbolDebug<'a, 'data, O: ObjectFile<'data>> {
    db: &'a SymbolDb<'data, O>,
    symbol_id: SymbolId,
    per_symbol_flags: &'a dyn FlagsForSymbol,
}

impl<'a, 'data, O: ObjectFile<'data>> std::fmt::Display for SymbolDebug<'a, 'data, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let symbol_id = self.symbol_id;
        let definition = self.db.definition(symbol_id);
        let file_id = self.db.file_id_for_symbol(symbol_id);
        let file = self.db.file(file_id);
        let symbol_id_range = file.symbol_id_range();

        if !symbol_id_range.contains(symbol_id) {
            write!(
                f,
                "SymbolId {symbol_id} is owned by {file_id}, but that file has range {}..{}",
                symbol_id_range.start(),
                symbol_id_range.start().add_usize(symbol_id_range.len())
            )?;
            // If ID ranges or file mappings are wrong, then the code later in this method, e.g.
            // `id_to_offset` or `symbol_name` will panic.
            return Ok(());
        }

        let local_index = symbol_id.to_offset(symbol_id_range);
        let symbol_name = self
            .db
            .symbol_name(symbol_id)
            .unwrap_or_else(|_| UnversionedSymbolName::new(b"??"));

        if definition.is_undefined() {
            write!(f, "undefined ")?;
        }

        if symbol_name.bytes().is_empty() {
            match file {
                SequencedInput::Prelude(_) => write!(f, "<unnamed internal symbol>")?,
                SequencedInput::Object(o) => {
                    let symbol_index = symbol_id.to_input(symbol_id_range);
                    if let Some(section_name) = o
                        .parsed
                        .object
                        .symbol(symbol_index)
                        .ok()
                        .and_then(|symbol| {
                            o.parsed
                                .object
                                .symbol_section(symbol, symbol_index)
                                .ok()
                                .flatten()
                        })
                        .map(|section_index| o.parsed.object.section_display_name(section_index))
                    {
                        write!(f, "section `{section_name}`")?;
                    } else {
                        write!(f, "<unnamed symbol>")?;
                    }
                }
                SequencedInput::LinkerScript(s) => {
                    write!(f, "Symbol from linker script `{}`", s.parsed.input)?;
                }
                SequencedInput::SyntheticSymbols(_) => {
                    write!(f, "<unnamed custom-section symbol>")?;
                }
                #[cfg(feature = "plugins")]
                SequencedInput::LtoInput(_) => write!(f, "<unnamed symbol from LTO object>")?,
            }
        } else {
            write!(f, "symbol `{}`", self.db.symbol_name_for_display(symbol_id))?;
        }

        write!(
            f,
            " ({symbol_id} local={local_index}) in file #{file_id} ({file})"
        )?;

        if symbol_id != definition && !definition.is_undefined() {
            let definition_file_id = self.db.file_id_for_symbol(definition);
            let definition_file = self.db.file(definition_file_id);
            write!(
                f,
                " defined as {definition} in file #{definition_file_id} ({definition_file})"
            )?;
        }

        let flags = self.per_symbol_flags.flags_for_symbol(symbol_id);
        write!(f, " ({flags})")?;

        Ok(())
    }
}

impl SymbolId {
    pub(crate) fn undefined() -> Self {
        Self(0)
    }

    pub(crate) fn from_usize(value: usize) -> SymbolId {
        Self::new(u32::try_from(value).expect("Symbols overflowed 32 bits"))
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }

    const fn new(value: u32) -> SymbolId {
        SymbolId(value)
    }

    pub(crate) fn offset_from(self, base: SymbolId) -> usize {
        (self.0 - base.0) as usize
    }

    pub(crate) fn to_offset(self, range: SymbolIdRange) -> usize {
        range.id_to_offset(self)
    }

    pub(crate) fn to_input(self, range: SymbolIdRange) -> object::SymbolIndex {
        range.id_to_input(self)
    }

    pub(crate) fn is_undefined(self) -> bool {
        self.0 == 0
    }

    pub(crate) fn next(self) -> Self {
        Self(self.0 + 1)
    }

    fn as_atomic(self) -> AtomicSymbolId {
        AtomicSymbolId(AtomicU32::new(self.0))
    }
}

impl AtomicSymbolId {
    fn store(&self, selected: SymbolId) {
        self.0.store(selected.0, Ordering::Relaxed);
    }

    fn into_non_atomic(self) -> SymbolId {
        SymbolId(self.0.into_inner())
    }
}

impl TryFrom<usize> for SymbolId {
    type Error = crate::error::Error;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        Ok(SymbolId(u32::try_from(value).context("Too many symbols")?))
    }
}

impl<'data> Prelude<'data> {
    fn load_symbols<O: ObjectFile<'data>>(
        &self,
        symbols_out: &mut SymbolWriterShard<'_, '_, 'data, O>,
        outputs: &mut SymbolLoadOutputs<'data>,
    ) {
        for definition in &self.symbol_definitions {
            let symbol_id = symbols_out.next;
            let flags = match definition.placement {
                SymbolPlacement::Undefined | SymbolPlacement::ForceUndefined => {
                    ValueFlags::ABSOLUTE
                }
                SymbolPlacement::DefsymAbsolute(_) => {
                    outputs.add_non_versioned(PendingSymbol::new(symbol_id, definition.name));
                    ValueFlags::NON_INTERPOSABLE | ValueFlags::ABSOLUTE
                }
                SymbolPlacement::SectionStart(_)
                | SymbolPlacement::SectionEnd(_)
                | SymbolPlacement::SectionGroupEnd(_)
                | SymbolPlacement::DefsymSymbol(_, _)
                | SymbolPlacement::LoadBaseAddress => {
                    outputs.add_non_versioned(PendingSymbol::new(symbol_id, definition.name));
                    ValueFlags::NON_INTERPOSABLE
                }
            };
            symbols_out.set_next(flags, symbol_id, PRELUDE_FILE_ID);
        }
    }
}

impl std::fmt::Display for SymbolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl InternalSymDefInfo<'_> {
    pub(crate) fn section_id(self) -> Option<OutputSectionId> {
        match self.placement {
            SymbolPlacement::Undefined
            | SymbolPlacement::ForceUndefined
            | SymbolPlacement::DefsymAbsolute(_)
            | SymbolPlacement::DefsymSymbol(_, _) => None,
            SymbolPlacement::SectionStart(i) => Some(i),
            SymbolPlacement::SectionEnd(i) => Some(i),
            SymbolPlacement::SectionGroupEnd(i) => Some(i),
            // The other linkers attach to the closest section, but the address is nonetheless
            // outside of the selected section. It's tricky for us to find the the closest section
            // at this point in the code, so we pick an arbitrary section.
            SymbolPlacement::LoadBaseAddress => Some(output_section_id::TEXT),
        }
    }
}

impl<'data> PendingSymbol<'data> {
    fn new(symbol_id: SymbolId, name: &'data [u8]) -> PendingSymbol<'data> {
        Self::from_prehashed(symbol_id, UnversionedSymbolName::prehashed(name))
    }

    fn from_prehashed(
        symbol_id: SymbolId,
        name: PreHashed<UnversionedSymbolName<'data>>,
    ) -> PendingSymbol<'data> {
        PendingSymbol { symbol_id, name }
    }
}

impl<'data> PendingVersionedSymbol<'data> {
    fn from_prehashed(
        symbol_id: SymbolId,
        name: PreHashed<UnversionedSymbolName<'data>>,
        version: &'data [u8],
    ) -> PendingVersionedSymbol<'data> {
        PendingVersionedSymbol {
            symbol_id,
            name: VersionedSymbolName::prehashed(name, version),
        }
    }
}

/// Decides how many buckets we should use for symbol names.
fn num_symbol_hash_buckets(args: &Args) -> usize {
    args.available_threads.get()
}

impl<'data> SymbolLoadOutputs<'data> {
    fn add_non_versioned(&mut self, pending: PendingSymbol<'data>) {
        let num_buckets = self.pending_symbols_by_bucket.len();

        self.pending_symbols_by_bucket[pending.name.hash() as usize % num_buckets]
            .symbols
            .push(pending);
    }

    fn add_versioned(&mut self, pending: PendingVersionedSymbol<'data>) {
        let num_buckets = self.pending_symbols_by_bucket.len();

        self.pending_symbols_by_bucket[pending.name.hash() as usize % num_buckets]
            .versioned_symbols
            .push(pending);
    }
}

impl<'data, 'db, O: ObjectFile<'data>> AtomicSymbolDb<'data, 'db, O> {
    fn input_symbol_visibility(&self, symbol_id: SymbolId) -> Visibility {
        self.db.input_symbol_visibility(symbol_id)
    }

    fn update_definition(&self, to_update: SymbolId, new_definition: SymbolId) {
        self.definitions[to_update.as_usize()].store(new_definition);
    }

    fn symbol_strength(&self, symbol_id: SymbolId, resolved: &[ResolvedGroup]) -> SymbolStrength {
        self.db.symbol_strength(symbol_id, resolved)
    }

    fn is_in_comdat_group(&self, symbol_id: SymbolId, resolved: &[ResolvedGroup]) -> bool {
        self.db.is_in_comdat_group(symbol_id, resolved)
    }

    fn symbol_name_for_display(&self, symbol_id: SymbolId) -> SymbolNameDisplay<'data> {
        self.db.symbol_name_for_display(symbol_id)
    }

    fn file(&'db self, file_id: FileId) -> SequencedInput<'db, 'data, O> {
        self.db.file(file_id)
    }

    fn file_id_for_symbol(&self, symbol_id: SymbolId) -> FileId {
        self.db.file_id_for_symbol(symbol_id)
    }
}

impl<'data, O: ObjectFile<'data>> Drop for AtomicSymbolDb<'data, '_, O> {
    fn drop(&mut self) {
        // Convert our atomic tables back to non-atomic tables and return them to the symbol-db that
        // we took them from. This operation should be basically free, at least in optimised builds.
        self.db.restore_definitions(
            take(&mut self.definitions)
                .into_iter()
                .map(|id| id.into_non_atomic())
                .collect(),
        );
    }
}

impl ShardKey for SymbolId {
    fn zero() -> Self {
        SymbolId(0)
    }

    fn add_usize(self, offset: usize) -> Self {
        SymbolId(
            (self.as_usize() + offset)
                .try_into()
                .expect("Symbol ID overflowed 32 bits"),
        )
    }
}

impl Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.name))?;
        if let Some(version) = self.version_name {
            if self.is_default {
                write!(f, "@@")?;
            } else {
                write!(f, "@")?;
            }
            write!(f, "{}", String::from_utf8_lossy(version))?;
        }

        Ok(())
    }
}

impl Display for SymbolNameDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = self.name {
            if let Ok(s) = std::str::from_utf8(name.bytes()) {
                if self.demangle {
                    Display::fmt(&symbolic_demangle::demangle(s), f)
                } else {
                    Display::fmt(s, f)
                }
            } else {
                write!(f, "INVALID UTF-8({:?})", name.bytes())
            }
        } else {
            write!(f, "SYMBOL-READ-ERROR")
        }
    }
}
