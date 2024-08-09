use crate::args::Args;
use crate::input_data::FileId;

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
