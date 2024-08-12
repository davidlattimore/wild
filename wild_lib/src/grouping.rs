use crate::args::Args;
use crate::input_data::FileId;
use crate::parsing::ParsedInput;
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
    let files_per_group = determine_files_per_group(files.len(), args);

    let mut groups = Vec::with_capacity(files.len() / files_per_group + 1);
    let mut group = Group::empty();
    for mut file in files {
        if group.files.len() >= files_per_group {
            groups.push(core::mem::replace(&mut group, Group::empty()));
        }
        file.set_file_id(FileId::new(groups.len() as u32, group.files.len() as u32));
        group.add_file(file);
    }
    if !group.files.is_empty() {
        groups.push(group);
    }
    groups
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
        .min(crate::input_data::MAX_FILES_PER_GROUP as usize)
}
