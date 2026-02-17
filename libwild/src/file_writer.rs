use crate::OutputKind;
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
use crate::timing_phase;
use crate::verbose_timing_phase;
use anyhow::anyhow;
use memmap2::MmapOptions;
use std::io::ErrorKind;
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
    config: OutputConfig,
}

#[derive(Clone, Copy)]
struct OutputConfig {
    file_write_mode: FileWriteMode,
    should_write_trace: bool,
    use_mmap: bool,
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
    fn new(file: &std::fs::File, file_size: u64, output_config: OutputConfig) -> Self {
        if output_config.use_mmap {
            // For some types of output file (e.g. character devices) we can't mmap, so we try to
            // mmap the file and if it fails, fall back to non-mmapped output.
            Self::new_mmapped(file, file_size)
                .unwrap_or_else(|| Self::InMemory(vec![0; file_size as usize]))
        } else {
            // Try to set the length of the file. We ignore failures here because it's expected to
            // fail for some types of files, e.g. /dev/null. If there's actually a problem writing
            // to the file, we'll discover that when we go to write the content later on.
            let _ = file.set_len(file_size);
            Self::InMemory(vec![0; file_size as usize])
        }
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
    pub(crate) fn new(args: &Args, output_kind: OutputKind) -> Output {
        let file_write_mode = args
            .file_write_mode
            .unwrap_or_else(|| default_file_write_mode(args, output_kind));

        let creator = if args.available_threads.get() > 1 {
            let (sized_output_sender, sized_output_recv) = std::sync::mpsc::channel();
            FileCreator::Background {
                sized_output_sender: Some(sized_output_sender),
                sized_output_recv,
            }
        } else {
            FileCreator::Regular { file_size: None }
        };

        Output {
            path: args.output.clone(),
            creator,
            config: OutputConfig {
                file_write_mode,
                should_write_trace: args.write_trace,
                use_mmap: args.mmap_output_file,
            },
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

                let output_config = self.config;

                rayon::spawn(move || {
                    verbose_timing_phase!("Create output file");

                    if output_config.file_write_mode == FileWriteMode::UnlinkAndReplace {
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
                    let sized_output = SizedOutput::new(path, output_config, size);

                    // Pass it to the main thread, so that it can start writing it once layout
                    // finishes.
                    let _ = sender.send(sized_output);
                });
            }
            FileCreator::Regular { file_size } => *file_size = Some(size),
        }
    }

    pub fn write<'data, 'layout>(
        &self,
        layout: &'layout Layout<'data>,
        write_fn: impl FnOnce(&mut SizedOutput, &'layout Layout<'data>) -> Result,
    ) -> Result {
        timing_phase!("Write output file");
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
            timing_phase!("Unmap output file");
            drop(sized_output);
        }

        Ok(())
    }

    fn create_file_non_lazily(&self, file_size: u64) -> Result<SizedOutput> {
        timing_phase!("Create output file");
        SizedOutput::new(self.path.clone(), self.config, file_size)
    }
}

/// Returns the file write mode that we should use to write to the specified path.
fn default_file_write_mode(args: &Args, output_kind: OutputKind) -> FileWriteMode {
    if output_kind.is_shared_object() {
        return FileWriteMode::UnlinkAndReplace;
    }

    if std::fs::metadata(&args.output).is_err() {
        return FileWriteMode::UnlinkAndReplace;
    };

    FileWriteMode::UpdateInPlaceWithFallback
}

/// Delete the old output file. Note, this is only used when running from a single thread.
fn delete_old_output(path: &Path) {
    timing_phase!("Delete old output");
    let _ = std::fs::remove_file(path);
}

fn wait_for_sized_output(sized_output_recv: &Receiver<Result<SizedOutput>>) -> Result<SizedOutput> {
    timing_phase!("Wait for output file creation");
    sized_output_recv.recv()?
}

impl SizedOutput {
    fn new(path: Arc<Path>, output_config: OutputConfig, file_size: u64) -> Result<SizedOutput> {
        let mut open_options = std::fs::OpenOptions::new();

        match output_config.file_write_mode {
            FileWriteMode::UnlinkAndReplace => {
                open_options.truncate(true);
            }
            FileWriteMode::UpdateInPlace | FileWriteMode::UpdateInPlaceWithFallback => {
                open_options.truncate(false);
            }
        }

        let file = match open_options.read(true).write(true).create(true).open(&path) {
            Ok(file) => file,
            Err(error) => {
                // Retry open operation with UnlinkAndReplace if it's an ETXTBSY error and
                // falllback is permitted.
                if error.kind() == ErrorKind::ExecutableFileBusy
                    && matches!(
                        output_config.file_write_mode,
                        FileWriteMode::UpdateInPlaceWithFallback
                    )
                {
                    // If the file is being executed, we can't modify it, but we can delete it.
                    std::fs::remove_file(&path)?;
                    open_options.create(true).open(&path)?
                } else {
                    return Err(error)
                        .with_context(|| format!("Failed to open `{}`", path.display()));
                }
            }
        };

        let out = OutputBuffer::new(&file, file_size, output_config);

        let trace = TraceOutput::new(output_config.should_write_trace, &path);

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

pub(crate) fn split_output_by_group<'layout, 'data, 'out>(
    layout: &'layout Layout<'data>,
    writable_buckets: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Vec<(
    &'layout GroupLayout<'data>,
    OutputSectionPartMap<&'out mut [u8]>,
)> {
    timing_phase!("Split output buffers by group");
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
        let Some(padding_size) = a.offset.checked_sub(offset) else {
            panic!(
                "Offsets went backward when splitting output file {offset} to {}",
                a.offset
            );
        };
        let padding = data.split_off_mut(..padding_size).unwrap();
        padding.fill(0);
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
                .ok_or_else(|| {
                    anyhow!(
                        "Failed to take {} bytes for section {} with alignment {}",
                        rec.file_size,
                        layout
                            .output_sections
                            .section_debug(part_id.output_section_id()),
                        part_id.alignment(),
                    )
                })
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
