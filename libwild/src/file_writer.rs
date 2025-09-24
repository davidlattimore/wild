use crate::args::Args;
use crate::args::FileWriteMode;
use crate::args::WRITE_VERIFY_ALLOCATIONS_ENV;
use crate::error;
use crate::error::Context as _;
use crate::error::Result;
use crate::layout::GroupLayout;
use crate::layout::Layout;
use crate::output_section_id::OutputSectionId;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::TraceOutput;
use memmap2::MmapOptions;
use std::io::Write;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

pub struct Output {
    path: Arc<Path>,
    creator: FileCreator,
    file_write_mode: FileWriteMode,
    should_write_trace: bool,
}

enum FileCreator {
    Background {
        sized_output_sender: Option<Sender<Result<SizedOutput>>>,
        sized_output_recv: Receiver<Result<SizedOutput>>,
    },
    Regular {
        file_size: Option<u64>,
    },
}

pub(crate) struct SizedOutput {
    file: std::fs::File,
    pub(crate) out: OutputBuffer,
    path: Arc<Path>,
    pub(crate) trace: TraceOutput,
}

pub(crate) enum OutputBuffer {
    Mmap(memmap2::MmapMut),
    InMemory(Vec<u8>),
}

impl OutputBuffer {
    fn new(file: &std::fs::File, file_size: u64) -> Self {
        Self::new_mmapped(file, file_size)
            .unwrap_or_else(|| Self::InMemory(vec![0; file_size as usize]))
    }

    fn new_mmapped(file: &std::fs::File, file_size: u64) -> Option<Self> {
        file.set_len(file_size).ok()?;
        let mmap = unsafe { MmapOptions::new().map_mut(file) }.ok()?;
        Some(Self::Mmap(mmap))
    }
}

impl Deref for OutputBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            OutputBuffer::Mmap(mmap) => mmap.deref(),
            OutputBuffer::InMemory(vec) => vec.deref(),
        }
    }
}

impl DerefMut for OutputBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            OutputBuffer::Mmap(mmap) => mmap.deref_mut(),
            OutputBuffer::InMemory(vec) => vec.deref_mut(),
        }
    }
}

#[derive(Debug)]
struct SectionAllocation {
    id: OutputSectionId,
    offset: usize,
    size: usize,
}

impl Output {
    pub(crate) fn new(args: &Args) -> Output {
        let file_write_mode = args
            .file_write_mode
            .unwrap_or_else(|| default_file_write_mode(&args.output));

        if args.available_threads.get() > 1 {
            let (sized_output_sender, sized_output_recv) = std::sync::mpsc::channel();
            Output {
                path: args.output.clone(),
                creator: FileCreator::Background {
                    sized_output_sender: Some(sized_output_sender),
                    sized_output_recv,
                },
                file_write_mode,
                should_write_trace: args.write_trace,
            }
        } else {
            Output {
                path: args.output.clone(),
                creator: FileCreator::Regular { file_size: None },
                file_write_mode,
                should_write_trace: args.write_trace,
            }
        }
    }

    pub(crate) fn set_size(&mut self, size: u64) {
        match &mut self.creator {
            FileCreator::Background {
                sized_output_sender,
                sized_output_recv: _,
            } => {
                let sender = sized_output_sender
                    .take()
                    .expect("set_size must only be called once");
                let path = self.path.clone();

                let write_mode = self.file_write_mode;
                let should_write_trace = self.should_write_trace;

                rayon::spawn(move || {
                    if write_mode == FileWriteMode::UnlinkAndReplace {
                        // Rename the old output file so that we can create a new file in its place.
                        // Reusing the existing file would also be an option, but that wouldn't
                        // error if the file is currently being executed.
                        let renamed_old_file = path.with_extension("delete");
                        let rename_status = std::fs::rename(&path, &renamed_old_file);

                        // If there was an old output file that we renamed, then delete it. We do so
                        // from a separate task so that it can run in the background while other
                        // threads continue working. Deleting can take a while for large files.
                        if rename_status.is_ok() {
                            rayon::spawn(move || {
                                let _ = std::fs::remove_file(renamed_old_file);
                                // Note, we don't currently signal when we've finished deleting the
                                // file. Based on experiments run on Linux 6.9.3, if we exit while
                                // an unlink syscall is in progress on a separate thread, Linux will
                                // wait for the unlink syscall to complete before terminating the
                                // process.
                            });
                        }
                    }

                    // Create the output file.
                    let sized_output = SizedOutput::new(path, size, write_mode, should_write_trace);

                    // Pass it to the main thread, so that it can start writing it once layout finishes.
                    let _ = sender.send(sized_output);
                });
            }
            FileCreator::Regular { file_size } => *file_size = Some(size),
        }
    }

    #[tracing::instrument(skip_all, name = "Write output file")]
    pub fn write<'data>(
        &self,
        layout: &Layout<'data>,
        write_fn: impl Fn(&mut SizedOutput, &Layout) -> Result,
    ) -> Result {
        if layout.args().write_layout {
            write_layout(layout)?;
        }
        let mut sized_output = match &self.creator {
            FileCreator::Background {
                sized_output_sender,
                sized_output_recv,
            } => {
                assert!(sized_output_sender.is_none(), "set_size was never called");
                wait_for_sized_output(sized_output_recv)?
            }
            FileCreator::Regular { file_size } => {
                delete_old_output(&self.path);
                let file_size = file_size.context("set_size was never called")?;
                self.create_file_non_lazily(file_size)?
            }
        };
        write_fn(&mut sized_output, layout)?;
        sized_output.flush()?;
        sized_output.trace.close()?;

        // While we have the output file mmapped with write permission, the file will be locked and
        // unusable, so we can't really say that we've finished writing it until we've unmapped it.
        {
            let _span = tracing::info_span!("Unmap output file").entered();
            drop(sized_output);
        }

        Ok(())
    }

    #[tracing::instrument(skip_all, name = "Create output file")]
    fn create_file_non_lazily(&self, file_size: u64) -> Result<SizedOutput> {
        SizedOutput::new(
            self.path.clone(),
            file_size,
            self.file_write_mode,
            self.should_write_trace,
        )
    }
}

/// Returns the file write mode that we should use to write to the specified path.
fn default_file_write_mode(path: &Path) -> FileWriteMode {
    use std::os::unix::fs::FileTypeExt as _;

    let Ok(metadata) = std::fs::metadata(path) else {
        return FileWriteMode::UnlinkAndReplace;
    };

    let file_type = metadata.file_type();

    // If we've been asked to write to a path that currently holds some exotic kind of file, then we
    // don't want to delete it, even if we have permission to. For example, we don't want to delete
    // `/dev/null` if we're running in a container as root.
    if file_type.is_char_device()
        || file_type.is_block_device()
        || file_type.is_socket()
        || file_type.is_fifo()
    {
        return FileWriteMode::UpdateInPlace;
    }

    FileWriteMode::UnlinkAndReplace
}

/// Delete the old output file. Note, this is only used when running from a single thread.
#[tracing::instrument(skip_all, name = "Delete old output")]
fn delete_old_output(path: &Path) {
    let _ = std::fs::remove_file(path);
}

#[tracing::instrument(skip_all, name = "Wait for output file creation")]
fn wait_for_sized_output(sized_output_recv: &Receiver<Result<SizedOutput>>) -> Result<SizedOutput> {
    sized_output_recv.recv()?
}

impl SizedOutput {
    fn new(
        path: Arc<Path>,
        file_size: u64,
        write_mode: FileWriteMode,
        should_write_trace: bool,
    ) -> Result<SizedOutput> {
        let mut open_options = std::fs::OpenOptions::new();

        // If another thread spawns a subprocess while we have this file open, we don't want the
        // subprocess to inherit our file descriptor. This unfortunately doesn't prevent that, since
        // unless and until the subprocess calls exec, it will inherit the file descriptor. However,
        // assuming it eventually calls exec, this at least means that it inherits the file
        // descriptor for less time. i.e. this doesn't really fix anything, but makes problems less bad.
        std::os::unix::fs::OpenOptionsExt::custom_flags(&mut open_options, libc::O_CLOEXEC);

        match write_mode {
            FileWriteMode::UnlinkAndReplace => {
                open_options.truncate(true);
            }
            FileWriteMode::UpdateInPlace => {
                open_options.truncate(false);
            }
        }

        let file = open_options
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .with_context(|| format!("Failed to open `{}`", path.display()))?;

        let out = OutputBuffer::new(&file, file_size);

        let trace = TraceOutput::new(should_write_trace, &path);

        Ok(SizedOutput {
            file,
            out,
            path,
            trace,
        })
    }

    fn flush(&mut self) -> Result {
        match &self.out {
            OutputBuffer::Mmap(_) => {}
            OutputBuffer::InMemory(bytes) => self
                .file
                .write_all(bytes)
                .with_context(|| format!("Failed to write to {}", self.path.display()))?,
        }

        // Making the file executable is best-effort only. For example if we're writing to a pipe or
        // something, it isn't going to work and that's OK.
        let _ = crate::fs::make_executable(&self.file);

        Ok(())
    }
}

pub(crate) fn insufficient_allocation(section_name: &str) -> crate::error::Error {
    error!(
        "Insufficient {section_name} allocation. {}",
        verify_allocations_message()
    )
}

pub(crate) fn excessive_allocation(
    section_name: &str,
    remaining: u64,
    allocated: u64,
) -> crate::error::Error {
    error!(
        "Allocated too much space in {section_name}. {remaining} of {allocated} bytes remain. {}",
        verify_allocations_message()
    )
}

/// Returns a message suggesting to set an environment variable to help debug a failure, but only if
/// it's not already set, since that would be confusing.
pub(crate) fn verify_allocations_message() -> String {
    if std::env::var(WRITE_VERIFY_ALLOCATIONS_ENV).is_ok_and(|v| v == "1") {
        String::new()
    } else {
        format!("Setting {WRITE_VERIFY_ALLOCATIONS_ENV}=1 might give more info")
    }
}

#[tracing::instrument(skip_all, name = "Split output buffers by group")]
pub(crate) fn split_output_by_group<'layout, 'data, 'out>(
    layout: &'layout Layout<'data>,
    writable_buckets: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Vec<(
    &'layout GroupLayout<'data>,
    OutputSectionPartMap<&'out mut [u8]>,
)> {
    layout
        .group_layouts
        .iter()
        .map(|group| (group, writable_buckets.take_mut(&group.file_sizes)))
        .collect()
}

pub(crate) fn split_output_into_sections<'out>(
    layout: &Layout,
    mut data: &'out mut [u8],
) -> OutputSectionMap<&'out mut [u8]> {
    let mut section_allocations = Vec::with_capacity(layout.section_layouts.len());
    layout.section_layouts.for_each(|id, s| {
        section_allocations.push(SectionAllocation {
            id,
            offset: s.file_offset,
            size: s.file_size,
        });
    });
    section_allocations.sort_by_key(|s| (s.offset, s.offset + s.size));

    // OutputSectionMap is ordered by section ID, which is not the same as output order. We
    // split the output file by output order, putting the relevant parts of the buffer into the
    // map.
    let mut section_data = OutputSectionMap::with_size(section_allocations.len());
    let mut offset = 0;
    for a in section_allocations {
        let Some(padding) = a.offset.checked_sub(offset) else {
            panic!(
                "Offsets went backward when splitting output file {offset} to {}",
                a.offset
            );
        };
        data.split_off_mut(..padding).unwrap();
        *section_data.get_mut(a.id) = data.split_off_mut(..a.size).unwrap();
        offset = a.offset + a.size;
    }
    section_data
}

/// Splits the writable buffers for each segment further into separate buffers for each alignment.
pub(crate) fn split_buffers_by_alignment<'out>(
    section_buffers: &'out mut OutputSectionMap<&mut [u8]>,
    layout: &Layout,
) -> OutputSectionPartMap<&'out mut [u8]> {
    layout.section_part_layouts.output_order_map(
        &layout.output_order,
        |part_id, _alignment, rec| {
            section_buffers
                .get_mut(part_id.output_section_id())
                .split_off_mut(..rec.file_size)
                .unwrap()
        },
    )
}

fn write_layout(layout: &Layout) -> Result {
    let layout_path = linker_layout::layout_path(&layout.args().output);
    write_layout_to(layout, &layout_path)
        .with_context(|| format!("Failed to write layout to `{}`", layout_path.display()))
}

fn write_layout_to(layout: &Layout, path: &Path) -> Result {
    let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
    layout.layout_data().write(&mut file)?;
    Ok(())
}
