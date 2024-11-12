use crate::args::Args;
use crate::input_data::FileId;
use crate::parsing::ParsedInput;
use crate::sharding::ShardKey as _;
use crate::symbol_db::SymbolId;

pub(crate) struct Group<'data> {
    pub(crate) files: Vec<ParsedInput<'data>>,
}
impl<'data> Group<'data> {
    pub(crate) fn start_symbol_id(&self) -> SymbolId {
        self.files[0].symbol_id_range().start()
    }

    fn empty() -> Self {
        Self {
            files: Default::default(),
        }
    }

    fn add_file(&mut self, file: ParsedInput<'data>) {
        self.files.push(file);
    }
}

pub(crate) fn group_files<'data>(files: Vec<ParsedInput<'data>>, args: &Args) -> Vec<Group<'data>> {
    let files_per_group = determine_max_files_per_group(args);
    let symbols_per_group = determine_symbols_per_group(&files, args);

    let mut groups = Vec::with_capacity(files.len() / files_per_group + 1);
    let mut group = Group::empty();
    let mut num_symbols = 0;
    for mut file in files {
        let mut num_symbols_with_file = num_symbols + file.symbol_id_range().len();

        // Start a new group if we've reached the maximum number of files for the group, or more
        // likely if the new file would put us over the per-group symbol limit.
        if group.files.len() >= files_per_group
            || (!group.files.is_empty() && num_symbols_with_file > symbols_per_group)
        {
            // Start a new group.
            groups.push(core::mem::replace(&mut group, Group::empty()));
            num_symbols_with_file = file.symbol_id_range().len();
        }
        num_symbols = num_symbols_with_file;
        file.set_file_id(FileId::new(groups.len() as u32, group.files.len() as u32));
        group.add_file(file);
    }
    if !group.files.is_empty() {
        groups.push(group);
    }
    groups
}

/// Decides after many symbols, we should start a new group.
fn determine_symbols_per_group(files: &[ParsedInput], args: &Args) -> usize {
    let num_symbols = files.last().map_or(0, |f| {
        f.symbol_id_range().start().as_usize() + f.symbol_id_range().len()
    });

    let num_threads = args.num_threads.get();

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
