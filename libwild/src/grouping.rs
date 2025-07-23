use crate::args::Args;
use crate::error::Result;
use crate::input_data::FileId;
use crate::input_data::MAX_FILES_PER_GROUP;
use crate::parsing::Epilogue;
use crate::parsing::ParsedInputObject;
use crate::parsing::ParsedInputs;
use crate::parsing::Prelude;
use crate::parsing::ProcessedLinkerScript;
use crate::sharding::ShardKey as _;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use std::fmt::Display;

pub(crate) enum Group<'data> {
    Prelude(Prelude<'data>),
    Objects(&'data [SequencedInputObject<'data>]),
    LinkerScripts(Vec<SequencedLinkerScript<'data>>),
    Epilogue(Epilogue),
}

pub(crate) struct SequencedInputObject<'data> {
    pub(crate) parsed: ParsedInputObject<'data>,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) file_id: FileId,
}

pub(crate) struct SequencedLinkerScript<'data> {
    pub(crate) parsed: ProcessedLinkerScript<'data>,
    pub(crate) symbol_id_range: SymbolIdRange,
    pub(crate) file_id: FileId,
}

pub(crate) enum SequencedInput<'data> {
    Prelude(&'data Prelude<'data>),
    Object(&'data SequencedInputObject<'data>),
    LinkerScript(&'data SequencedLinkerScript<'data>),
    Epilogue(&'data Epilogue),
}

impl Group<'_> {
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
            Group::Epilogue(o) => SymbolIdRange::epilogue(o.start_symbol_id, 0),
        }
    }

    pub(crate) fn num_symbols(&self) -> usize {
        self.symbol_id_range().len()
    }
}

#[tracing::instrument(skip_all, name = "Group files")]
pub(crate) fn group_files<'data>(
    parsed_inputs: ParsedInputs<'data>,
    args: &Args,
    herd: &'data bumpalo_herd::Herd,
) -> Vec<Group<'data>> {
    let max_files_per_group = determine_max_files_per_group(args);
    let symbols_per_group = determine_symbols_per_group(&parsed_inputs, args);

    let mut groups = Vec::with_capacity(parsed_inputs.objects.len() / max_files_per_group + 3);

    let mut next_symbol_id = SymbolId::undefined();
    next_symbol_id = next_symbol_id.add_usize(parsed_inputs.prelude.symbol_definitions.len());
    groups.push(Group::Prelude(parsed_inputs.prelude));

    let mut objects = parsed_inputs.objects.into_iter().peekable();

    let mut num_symbols_in_group = 0;
    let mut group_objects = Vec::new();

    let allocator = herd.get();

    while let Some(obj) = objects.next() {
        let file_id = FileId::new(groups.len() as u32, group_objects.len() as u32);
        let num_symbols_in_file = obj.object.symbols.len();

        group_objects.push(SequencedInputObject {
            parsed: obj,
            symbol_id_range: SymbolIdRange::input(next_symbol_id, num_symbols_in_file),
            file_id,
        });

        next_symbol_id = next_symbol_id.add_usize(num_symbols_in_file);

        num_symbols_in_group += num_symbols_in_file;

        // Finish the current group if we've reached the maximum number of files for the group, if
        // this is the last file or if the next file would put us over the per-group symbol limit.
        let finish_group = group_objects.len() >= max_files_per_group
            || objects.peek().is_none_or(|next_obj| {
                num_symbols_in_group + next_obj.object.symbols.len() > symbols_per_group
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

            groups.push(Group::Objects(objects_slice));
        }
    }

    let linker_scripts = parsed_inputs
        .linker_scripts
        .into_iter()
        .enumerate()
        .map(|(i, script)| {
            let symbol_id_range = SymbolIdRange::input(next_symbol_id, script.num_symbols());
            next_symbol_id = next_symbol_id.add_usize(symbol_id_range.len());

            SequencedLinkerScript {
                parsed: script,
                file_id: FileId::new(groups.len() as u32, i as u32),
                symbol_id_range,
            }
        })
        .collect();

    groups.push(Group::LinkerScripts(linker_scripts));

    groups.push(Group::Epilogue(Epilogue {
        file_id: FileId::new(groups.len() as u32, 0),
        start_symbol_id: next_symbol_id,
    }));

    tracing::trace!("GROUPS:\n{}", GroupsDisplay(&groups));

    groups
}

/// Decides after how many symbols, we should start a new group.
fn determine_symbols_per_group(parsed_inputs: &ParsedInputs, args: &Args) -> usize {
    let num_threads = args.available_threads.get();

    // If we're running with a single thread, then we might as well put everything into a single
    // group.
    if num_threads == 1 {
        return usize::MAX;
    }

    // This value is roughly picked based on some very basic benchmarks, so might not be optimal.
    // Setting it lower reduces the number of groups and thus reduces the per-group overhead,
    // however larger groups means a higher likelihood that one group will finish significantly
    // after the others.
    const GROUPS_PER_THREAD: usize = 30;

    1.max(parsed_inputs.num_symbols / num_threads / GROUPS_PER_THREAD)
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

struct GroupsDisplay<'a, 'data>(&'a [Group<'data>]);

impl<'data> SequencedInputObject<'data> {
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

    /// Returns whether this input should be skipped if there are no non-weak references to symbols
    /// it defines. This is true for archive entries for which --whole-archive is false and shared
    /// objects for which --as-needed is true.
    pub(crate) fn is_optional(&self) -> bool {
        (self.parsed.input.has_archive_semantics() && !self.parsed.modifiers.whole_archive)
            || (self.is_dynamic() && self.parsed.modifiers.as_needed)
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        self.parsed.is_dynamic
    }
}

impl<'data> SequencedLinkerScript<'data> {
    pub(crate) fn symbol_name(&self, symbol_id: SymbolId) -> UnversionedSymbolName<'data> {
        let local_index = self.symbol_id_range.id_to_offset(symbol_id);
        UnversionedSymbolName::new(self.parsed.symbol_defs[local_index].name)
    }
}

impl SequencedInput<'_> {
    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        match self {
            SequencedInput::Prelude(o) => SymbolIdRange::prelude(o.symbol_definitions.len()),
            SequencedInput::Object(o) => o.symbol_id_range,
            SequencedInput::LinkerScript(o) => o.symbol_id_range,
            SequencedInput::Epilogue(o) => SymbolIdRange::epilogue(
                o.start_symbol_id,
                // The epilogue allocates symbols after inputs are parsed, so it effectively owns
                // the rest of the symbol ID space.
                u32::MAX as usize - o.start_symbol_id.as_usize(),
            ),
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

impl Display for GroupsDisplay<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, group) in self.0.iter().enumerate() {
            writeln!(f, "{i}: {group}")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for SequencedInputObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.parsed.input, f)
    }
}

impl Display for Group<'_> {
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
            Group::Epilogue(_) => write!(f, "<epilogue>"),
        }
    }
}

impl std::fmt::Display for SequencedInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SequencedInput::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            SequencedInput::Object(o) => std::fmt::Display::fmt(o, f),
            SequencedInput::LinkerScript(o) => std::fmt::Display::fmt(&o.parsed, f),
            SequencedInput::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
        }
    }
}
