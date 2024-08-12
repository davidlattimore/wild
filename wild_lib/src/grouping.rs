use crate::args::Args;
use crate::input_data::FileId;
use crate::parsing::ParsedInput;
use crate::symbol_db::SymbolId;

#[derive(Copy, Clone)]
pub(crate) struct Grouping {
    pub(crate) files_per_group: usize,
}

impl Grouping {
    pub(crate) fn new(num_files: usize, args: &Args) -> Self {
        Self {
            files_per_group: determine_files_per_group(num_files, args),
        }
    }

    pub(crate) fn group_index_for_file(self, file_id: FileId) -> usize {
        file_id.as_usize() / self.files_per_group
    }

    pub(crate) fn parts(self, file_id: FileId) -> (usize, usize) {
        let group_index = file_id.as_usize() / self.files_per_group;
        let file_in_group = file_id.as_usize() % self.files_per_group;
        (group_index, file_in_group)
    }
}

/// Determines how many files per group. For now, we only support a fixed number of files per group
/// for all groups except the last group. Eventually, we may want to experiment with a variable
/// number of files, since that would allow us to have less files in groups where the files are
/// large.
fn determine_files_per_group(num_files: usize, args: &Args) -> usize {
    if let Some(v) = args.files_per_group {
        return v as usize;
    }
    let num_threads = args.num_threads.get();

    // If we're running with a single thread, then we might as well put everything into a single
    // group.
    if num_threads == 1 {
        return 1;
    }

    // This value is roughly picked based on some very basic benchmarks, so might not be optimal.
    // Setting it lower reduces the number of groups and thus reduces the per-group overhead,
    // however larger groups means a higher likelihood that one group will finish significantly
    // after the others.
    const GROUPS_PER_THREAD: usize = 30;

    1.max(num_files / num_threads / GROUPS_PER_THREAD)
}

pub(crate) struct Group<'data> {
    pub(crate) files: Vec<ParsedInput<'data>>,
}
impl<'data> Group<'data> {
    pub(crate) fn base_file_id(&self) -> FileId {
        self.files.first().unwrap().file_id()
    }

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

pub(crate) fn group_files(files: Vec<ParsedInput>, grouping: Grouping) -> Vec<Group> {
    let mut groups = Vec::with_capacity(files.len() / grouping.files_per_group + 1);
    let mut group = Group::empty();
    for file in files {
        if group.files.len() >= grouping.files_per_group {
            groups.push(core::mem::replace(&mut group, Group::empty()));
        }
        group.add_file(file);
    }
    if !group.files.is_empty() {
        groups.push(group);
    }
    groups
}
