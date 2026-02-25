use crate::args::Args;
use crate::error::Result;
use crate::input_data::FileId;
use crate::input_data::MAX_FILES_PER_GROUP;
use crate::parsing::ParsedInputObject;
use crate::parsing::Prelude;
use crate::parsing::ProcessedLinkerScript;
use crate::parsing::SyntheticSymbols;
use crate::platform::ObjectFile;
use crate::sharding::ShardKey as _;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::timing_phase;
use crate::verbose_timing_phase;
use std::fmt::Display;

#[derive(Debug)]
pub(crate) enum Group<'data, O: ObjectFile<'data>> {
    Prelude(Prelude<'data>),
    Objects(&'data [SequencedInputObject<'data, O>]),
    LinkerScripts(Vec<SequencedLinkerScript<'data>>),
    SyntheticSymbols(SyntheticSymbols),
    #[cfg(feature = "plugins")]
    LtoInputs(Vec<crate::linker_plugins::LtoInput<'data>>),
}

#[derive(Debug)]
pub(crate) struct SequencedInputObject<'data, O: ObjectFile<'data>> {
    pub(crate) parsed: Box<ParsedInputObject<'data, O>>,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) file_id: FileId,
}

#[derive(Debug)]
pub(crate) struct SequencedLinkerScript<'data> {
    pub(crate) parsed: ProcessedLinkerScript<'data>,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) file_id: FileId,
}

#[derive(Debug)]
pub(crate) enum SequencedInput<'db, 'data, O: ObjectFile<'data>> {
    Prelude(&'db Prelude<'data>),
    Object(&'data SequencedInputObject<'data, O>),
    LinkerScript(&'db SequencedLinkerScript<'data>),
    SyntheticSymbols(&'db SyntheticSymbols),
    #[cfg(feature = "plugins")]
    LtoInput(&'db crate::linker_plugins::LtoInput<'data>),
}

impl<'data, O: ObjectFile<'data>> Group<'data, O> {
    // This is used when the verbose-ttttiming feature is enabled.
    pub(crate) fn group_id(&self) -> usize {
        match self {
            Group::Prelude(_) => 0,
            Group::Objects(objects) => objects[0].file_id.group(),
            Group::LinkerScripts(scripts) => scripts[0].file_id.group(),
            Group::SyntheticSymbols(s) => s.file_id.group(),
            #[cfg(feature = "plugins")]
            Group::LtoInputs(s) => s[0].file_id.group(),
        }
    }

    pub(crate) fn start_symbol_id(&self) -> SymbolId {
        self.symbol_id_range().start()
    }

    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            Group::Prelude(o) => SymbolIdRange::prelude(o.symbol_definitions.len()),
            Group::Objects(objects) => SymbolIdRange::covering(
                objects[0].symbol_id_range,
                objects[objects.len() - 1].symbol_id_range,
            ),
            Group::LinkerScripts(scripts) => {
                if scripts.is_empty() {
                    SymbolIdRange::empty()
                } else {
                    SymbolIdRange::covering(
                        scripts[0].symbol_id_range,
                        scripts[scripts.len() - 1].symbol_id_range,
                    )
                }
            }
            Group::SyntheticSymbols(o) => o.symbol_id_range,
            #[cfg(feature = "plugins")]
            Group::LtoInputs(objects) => SymbolIdRange::covering(
                objects[0].symbol_id_range,
                objects[objects.len() - 1].symbol_id_range,
            ),
        }
    }

    pub(crate) fn num_symbols(&self) -> usize {
        self.symbol_id_range().len()
    }
}

pub(crate) fn create_groups<'data, O: ObjectFile<'data>>(
    symbol_db: &mut SymbolDb<'data, O>,
    parsed_objects: Vec<Box<ParsedInputObject<'data, O>>>,
    linker_scripts: Vec<ProcessedLinkerScript<'data>>,
) {
    timing_phase!("Group files");

    let max_files_per_group = determine_max_files_per_group(symbol_db.args);
    let num_symbols = count_symbols(&parsed_objects);
    let symbols_per_group = determine_symbols_per_group(num_symbols, symbol_db.args);

    symbol_db.groups_reserve(parsed_objects.len() / max_files_per_group + 3);

    let mut next_symbol_id = symbol_db.next_symbol_id();

    let mut objects = parsed_objects.into_iter().peekable();

    let mut num_symbols_in_group = 0;
    let mut group_objects = Vec::new();

    let allocator = symbol_db.herd.get();

    while let Some(parsed) = objects.next() {
        let file_id = FileId::new(symbol_db.next_group_index(), group_objects.len() as u32);
        let num_symbols_in_file = parsed.object.num_symbols();

        group_objects.push(SequencedInputObject {
            parsed,
            symbol_id_range: SymbolIdRange::input(next_symbol_id, num_symbols_in_file),
            file_id,
        });

        next_symbol_id = next_symbol_id.add_usize(num_symbols_in_file);

        num_symbols_in_group += num_symbols_in_file;

        // Finish the current group if we've reached the maximum number of files for the group, if
        // this is the last file or if the next file would put us over the per-group symbol limit.
        let finish_group = group_objects.len() >= max_files_per_group
            || objects.peek().is_none_or(|next_obj| {
                num_symbols_in_group + next_obj.object.num_symbols() > symbols_per_group
            });

        if finish_group {
            num_symbols_in_group = 0;

            debug_assert!(
                group_objects.len() <= MAX_FILES_PER_GROUP as usize,
                "Group is too large: {}",
                group_objects.len()
            );

            let objects_slice =
                allocator.alloc_slice_fill_iter(core::mem::take(&mut group_objects));

            symbol_db.add_group(Group::Objects(objects_slice));
        }
    }

    let linker_scripts: Vec<SequencedLinkerScript<'_>> = linker_scripts
        .into_iter()
        .enumerate()
        .map(|(i, script)| {
            let symbol_id_range = SymbolIdRange::input(next_symbol_id, script.num_symbols());
            next_symbol_id = next_symbol_id.add_usize(symbol_id_range.len());

            SequencedLinkerScript {
                parsed: script,
                file_id: FileId::new(symbol_db.next_group_index(), i as u32),
                symbol_id_range,
            }
        })
        .collect();

    if !linker_scripts.is_empty() {
        symbol_db.add_group(Group::LinkerScripts(linker_scripts));
    }

    tracing::trace!(
        "GROUPS:\n{}",
        std::fmt::from_fn(|f| {
            for (i, group) in symbol_db.groups.iter().enumerate() {
                writeln!(f, "{i}: {group}")?;
            }
            Ok(())
        })
    );
}

/// Decides after how many symbols, we should start a new group.
fn determine_symbols_per_group(num_symbols: usize, args: &Args) -> usize {
    let num_threads = args.available_threads.get();

    // If we're running with a single thread, then we might as well put everything into a single
    // group.
    if num_threads == 1 {
        return usize::MAX;
    }

    // If we have lots of threads, then we might benefit from a few more groups in order to properly
    // take advantage of the available parallelism.
    let groups_per_thread =
        args.numeric_experiment(crate::args::Experiment::GroupsPerThread, 5) as usize;

    // If we don't have lots of threads, then we still want a reasonable number of groups. The need
    // for this was based on experimentation.
    let min_groups = args.numeric_experiment(crate::args::Experiment::MinGroups, 150) as usize;

    let target_num_groups = (num_threads * groups_per_thread).max(min_groups);

    1.max(num_symbols / target_num_groups)
}

/// Decides the maximum number of files that we'll put into one group.
fn determine_max_files_per_group(args: &Args) -> usize {
    if let Some(v) = args.files_per_group {
        return v as usize;
    }

    // We may eventually find that a lower value based on the number of threads is better, but for
    // now, if files are small, we allow lots of them in a single group.
    crate::input_data::MAX_FILES_PER_GROUP as usize
}

/// Compute the total number of symbols in the supplied objects.
fn count_symbols<'data, O: ObjectFile<'data>>(
    objects: &[Box<ParsedInputObject<'data, O>>],
) -> usize {
    verbose_timing_phase!("Count symbols");

    objects.iter().map(|o| o.num_symbols()).sum::<usize>()
}

impl<'data, O: ObjectFile<'data>> SequencedInputObject<'data, O> {
    pub(crate) fn symbol_name(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Result<UnversionedSymbolName<'data>> {
        let index = symbol_id.to_input(self.symbol_id_range);
        let symbol = self.parsed.object.symbol(index)?;
        Ok(UnversionedSymbolName::new(
            self.parsed.object.symbol_name(symbol)?,
        ))
    }

    /// Get the version of a symbol. Only intended for diagnostic purposes since it's potentially
    /// quite slow.
    pub(crate) fn symbol_version_debug(
        &self,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> Option<String> {
        self.parsed
            .object
            .symbol_version_debug(symbol_id.to_input(self.symbol_id_range))
    }

    /// Returns whether this input should be skipped if there are no non-weak references to symbols
    /// it defines. This is true for archive entries for which --whole-archive is false and shared
    /// objects for which --as-needed is true.
    pub(crate) fn is_optional(&self) -> bool {
        (self.parsed.input.has_archive_semantics() && !self.parsed.modifiers.whole_archive)
            || (self.is_dynamic() && self.parsed.modifiers.as_needed)
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        self.parsed.object.is_dynamic()
    }
}

impl<'data> SequencedLinkerScript<'data> {
    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> UnversionedSymbolName<'data> {
        let local_index = self.symbol_id_range.id_to_offset(symbol_id);
        UnversionedSymbolName::new(self.parsed.symbol_defs[local_index].name)
    }
}

impl<'db, 'data, O: ObjectFile<'data>> SequencedInput<'db, 'data, O> {
    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            SequencedInput::Prelude(o) => SymbolIdRange::prelude(o.symbol_definitions.len()),
            SequencedInput::Object(o) => o.symbol_id_range,
            SequencedInput::LinkerScript(o) => o.symbol_id_range,
            SequencedInput::SyntheticSymbols(o) => o.symbol_id_range,
            #[cfg(feature = "plugins")]
            SequencedInput::LtoInput(o) => o.symbol_id_range,
        }
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        if let SequencedInput::Object(o) = self {
            o.is_dynamic()
        } else {
            false
        }
    }
}

impl<'data, O: ObjectFile<'data>> std::fmt::Display for SequencedInputObject<'data, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.parsed.input, f)
    }
}

impl<'data, O: ObjectFile<'data>> Display for Group<'data, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Group::Prelude(_) => write!(f, "<prelude>"),
            Group::Objects(parsed_input_objects) => {
                let num_symbols: usize = parsed_input_objects
                    .iter()
                    .map(|o| o.symbol_id_range.len())
                    .sum();

                write!(
                    f,
                    "num_objects: {num_objects} num_symbols: {num_symbols}",
                    num_objects = parsed_input_objects.len(),
                )
            }
            Group::LinkerScripts(scripts) => write!(f, "{} linker script(s)", scripts.len()),
            Group::SyntheticSymbols(_) => write!(f, "<epilogue>"),
            #[cfg(feature = "plugins")]
            Group::LtoInputs(lto_inputs) => write!(f, "<{} lto inputs>", lto_inputs.len()),
        }
    }
}

impl<'db, 'data, O: ObjectFile<'data>> std::fmt::Display for SequencedInput<'db, 'data, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SequencedInput::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            SequencedInput::Object(o) => std::fmt::Display::fmt(o, f),
            SequencedInput::LinkerScript(o) => std::fmt::Display::fmt(&o.parsed, f),
            SequencedInput::SyntheticSymbols(_) => std::fmt::Display::fmt("<epilogue>", f),
            #[cfg(feature = "plugins")]
            SequencedInput::LtoInput(o) => std::fmt::Display::fmt(o, f),
        }
    }
}
