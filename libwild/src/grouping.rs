use crate::args::Args;
use crate::input_data::FileId;
use crate::input_data::MAX_FILES_PER_GROUP;
use crate::parsing::Epilogue;
use crate::parsing::ParsedInputObject;
use crate::parsing::ParsedInputs;
use crate::parsing::Prelude;
use crate::parsing::ProcessedLinkerScript;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use std::fmt::Display;

pub(crate) enum Group<'data> {
    Prelude(Prelude<'data>),
    Objects(&'data [ParsedInputObject<'data>]),
    LinkerScripts(Vec<ProcessedLinkerScript<'data>>),
    Epilogue(Epilogue),
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

pub(crate) fn group_files<'data>(
    parsed_inputs: ParsedInputs<'data>,
    args: &Args,
) -> Vec<Group<'data>> {
    let files_per_group = determine_max_files_per_group(args);
    let symbols_per_group = determine_symbols_per_group(&parsed_inputs, args);

    let mut groups = Vec::with_capacity(parsed_inputs.objects.len() / files_per_group + 3);

    groups.push(Group::Prelude(parsed_inputs.prelude));

    let mut num_symbols = parsed_inputs
        .objects
        .first()
        .map_or(0, |obj| obj.symbol_id_range.len());
    let mut num_files = 1;

    groups.extend(
        parsed_inputs
            .objects
            .chunk_by_mut(|_, obj| {
                let num_file_symbols = obj.symbol_id_range.len();

                // Finish the current group if we've reached the maximum number of files for the group, if
                // the new file would put us over the per-group symbol limit.
                let start_new = num_files >= files_per_group
                    || (num_files > 0 && num_symbols + num_file_symbols > symbols_per_group);

                if start_new {
                    num_files = 0;
                    num_symbols = 0;
                }

                num_files += 1;
                num_symbols += num_file_symbols;

                !start_new
            })
            .enumerate()
            .map(|(i, group_objects)| {
                debug_assert!(
                    group_objects.len() <= MAX_FILES_PER_GROUP as usize,
                    "Group is too large: {}",
                    group_objects.len()
                );

                for (file_number, obj) in group_objects.iter_mut().enumerate() {
                    obj.set_file_id(FileId::new(i as u32 + 1, file_number as u32));
                }

                Group::Objects(group_objects)
            }),
    );

    let mut linker_scripts = parsed_inputs.linker_scripts;
    for (i, script) in linker_scripts.iter_mut().enumerate() {
        script.file_id = FileId::new(groups.len() as u32, i as u32);
    }
    groups.push(Group::LinkerScripts(linker_scripts));

    let mut epilogue = parsed_inputs.epilogue;
    epilogue.file_id = FileId::new(groups.len() as u32, 0);
    groups.push(Group::Epilogue(epilogue));

    tracing::trace!("GROUPS:\n{}", GroupsDisplay(&groups));

    groups
}

/// Decides after how many symbols, we should start a new group.
fn determine_symbols_per_group(parsed_inputs: &ParsedInputs, args: &Args) -> usize {
    let num_symbols = parsed_inputs.num_symbols();

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

    1.max(num_symbols / num_threads / GROUPS_PER_THREAD)
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

impl Display for GroupsDisplay<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, group) in self.0.iter().enumerate() {
            writeln!(f, "{i}: {group}")?;
        }
        Ok(())
    }
}

impl Display for Group<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Group::Prelude(_) => write!(f, "<prelude>"),
            Group::Objects(parsed_input_objects) => {
                write!(f, "{} object(s)", parsed_input_objects.len())
            }
            Group::LinkerScripts(scripts) => write!(f, "{} linker script(s)", scripts.len()),
            Group::Epilogue(_) => write!(f, "<epilogue>"),
        }
    }
}
