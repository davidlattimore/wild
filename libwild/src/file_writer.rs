use crate::FileSystem;
use crate::OutputFileData;
use crate::OutputKind;
use crate::OutputOptions;
use crate::args::WRITE_VERIFY_ALLOCATIONS_ENV;
use crate::env;
use crate::error;
use crate::error::Context as _;
use crate::error::Result;
use crate::fs::FileReplacementMode;
use crate::fs::FileWriteMode;
use crate::layout::GroupLayout;
use crate::layout::Layout;
use crate::output_section_id::OutputSectionId;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::output_trace::TraceOutput;
use crate::platform;
use crate::platform::Args;
use crate::platform::Platform;
use crate::timing_phase;
use crate::verbose_timing_phase;
use anyhow::anyhow;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use rayon::slice::ParallelSliceMut;
use std::ops::Deref;
use std::ops::DerefMut;
use std::path::Path;
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::Sender;

pub struct Output<F: FileSystem> {
    path: Arc<Path>,
    creator: FileCreator<F::Output>,
    config: OutputConfig,
    file_system: Arc<F>,
}

#[derive(Clone, Copy)]
struct OutputConfig {
    file_replacement_mode: FileReplacementMode,
    should_write_trace: bool,
    file_write_mode: Option<FileWriteMode>,
}

enum FileCreator<O: OutputFileData> {
    Background {
        sized_output_sender: Option<Sender<Result<SizedOutput<O>>>>,
        sized_output_recv: Receiver<Result<SizedOutput<O>>>,
    },
    Regular {
        file_size: Option<u64>,
    },
}

pub(crate) struct SizedOutput<O: OutputFileData> {
    pub(crate) out: OutputBuffer<O>,
    pub(crate) trace: TraceOutput,
}

pub(crate) struct OutputBuffer<O: OutputFileData>(O);

impl<O: OutputFileData> OutputBuffer<O> {
    pub(crate) fn invalidate(&mut self, len: usize) {
        self.0.invalidate(len);
    }

    fn finish(self) -> Result {
        self.0.finish()
    }
}

impl<O: OutputFileData> Deref for OutputBuffer<O> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.bytes()
    }
}

impl<O: OutputFileData> DerefMut for OutputBuffer<O> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.bytes_mut()
    }
}

#[derive(Debug)]
struct SectionAllocation {
    id: OutputSectionId,
    offset: usize,
    size: usize,
}

impl<F: FileSystem> Output<F> {
    pub(crate) fn new(
        args: &impl platform::Args,
        output_kind: OutputKind,
        file_system: Arc<F>,
    ) -> Output<F> {
        let file_replacement_mode = args.common().file_replacement_mode.unwrap_or_else(|| {
            default_file_replacement_mode(args, output_kind, file_system.as_ref())
        });

        let creator = if args.common().available_threads.get() > 1 {
            let (sized_output_sender, sized_output_recv) = std::sync::mpsc::channel();
            FileCreator::Background {
                sized_output_sender: Some(sized_output_sender),
                sized_output_recv,
            }
        } else {
            FileCreator::Regular { file_size: None }
        };

        Output {
            path: args.output().clone(),
            file_system,
            creator,
            config: OutputConfig {
                file_replacement_mode,
                should_write_trace: args.common().write_trace,
                file_write_mode: args.common().file_write_mode,
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
                let file_system = Arc::clone(&self.file_system);

                rayon::spawn(move || {
                    verbose_timing_phase!("Create output file");

                    if output_config.file_replacement_mode == FileReplacementMode::UnlinkAndReplace
                    {
                        // Rename the old output file so that we can create a new file in its place.
                        // Reusing the existing file would also be an option, but that wouldn't
                        // error if the file is currently being executed.
                        let renamed_old_file = path.with_extension("delete");
                        let rename_status = file_system.rename_file(&path, &renamed_old_file);

                        // If there was an old output file that we renamed, then delete it. We do so
                        // from a separate task so that it can run in the background while other
                        // threads continue working. Deleting can take a while for large files.
                        if rename_status.is_ok() {
                            let file_system = Arc::clone(&file_system);
                            rayon::spawn(move || {
                                let _ = file_system.remove_file(&renamed_old_file);
                                // Note, we don't currently signal when we've finished deleting the
                                // file. Based on experiments run on Linux 6.9.3, if we exit while
                                // an unlink syscall is in progress on a separate thread, Linux will
                                // wait for the unlink syscall to complete before terminating the
                                // process.
                            });
                        }
                    }

                    // Create the output file.
                    let sized_output = SizedOutput::new(&file_system, &path, output_config, size);

                    // Pass it to the main thread, so that it can start writing it once layout
                    // finishes.
                    let _ = sender.send(sized_output);
                });
            }
            FileCreator::Regular { file_size } => *file_size = Some(size),
        }
    }

    pub fn write<'data, 'layout, P: Platform>(
        &self,
        layout: &'layout Layout<'data, P>,
        write_fn: impl FnOnce(&mut SizedOutput<F::Output>, &'layout Layout<'data, P>) -> Result,
    ) -> Result {
        timing_phase!("Write output file");
        if layout.args().common().write_layout {
            write_layout(layout, self.file_system.as_ref())?;
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
                delete_old_output(self.file_system.as_ref(), &self.path);
                let file_size = file_size.context("set_size was never called")?;
                self.create_file_non_lazily(file_size)?
            }
        };
        write_fn(&mut sized_output, layout)?;
        sized_output.trace.close(self.file_system.as_ref())?;

        // While we have the output file mmapped with write permission, the file will be locked and
        // unusable, so we can't really say that we've finished writing it until we've unmapped it.
        {
            timing_phase!("Flush and unmap output file");
            sized_output.flush()?;
        }

        Ok(())
    }

    fn create_file_non_lazily(&self, file_size: u64) -> Result<SizedOutput<F::Output>> {
        timing_phase!("Create output file");
        SizedOutput::new(&self.file_system, &self.path, self.config, file_size)
    }
}

/// Returns the file replacement mode that we should use to write to the specified path.
fn default_file_replacement_mode(
    args: &impl platform::Args,
    output_kind: OutputKind,
    file_system: &impl FileSystem,
) -> FileReplacementMode {
    if output_kind.is_shared_object() {
        return FileReplacementMode::UnlinkAndReplace;
    }

    if file_system.file_type(args.output()).is_err() {
        return FileReplacementMode::UnlinkAndReplace;
    }

    FileReplacementMode::UpdateInPlaceWithFallback
}

/// Delete the old output file. Note, this is only used when running from a single thread.
fn delete_old_output(file_system: &impl FileSystem, path: &Path) {
    timing_phase!("Delete old output");
    let _ = file_system.remove_file(path);
}

fn wait_for_sized_output<O: OutputFileData>(
    sized_output_recv: &Receiver<Result<SizedOutput<O>>>,
) -> Result<SizedOutput<O>> {
    timing_phase!("Wait for output file creation");
    sized_output_recv.recv()?
}

impl<O: OutputFileData> SizedOutput<O> {
    fn new<F: FileSystem<Output = O>>(
        file_system: &Arc<F>,
        path: &Arc<Path>,
        output_config: OutputConfig,
        file_size: u64,
    ) -> Result<SizedOutput<O>> {
        let output = file_system.create_output(
            path.clone(),
            OutputOptions {
                size: file_size,
                file_replacement_mode: output_config.file_replacement_mode,
                write_mode: output_config.file_write_mode,
            },
        )?;
        let trace = TraceOutput::new(output_config.should_write_trace, path);
        Ok(SizedOutput {
            out: OutputBuffer(output),
            trace,
        })
    }

    fn flush(self) -> Result {
        self.out.finish()
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
    if env::var(WRITE_VERIFY_ALLOCATIONS_ENV).is_ok_and(|v| v == "1") {
        String::new()
    } else {
        format!("Setting {WRITE_VERIFY_ALLOCATIONS_ENV}=1 might give more info")
    }
}

pub(crate) fn split_output_by_group<'layout, 'data, 'out, P: Platform>(
    layout: &'layout Layout<'data, P>,
    writable_buckets: &'out mut OutputSectionPartMap<&mut [u8]>,
) -> Vec<(
    &'layout GroupLayout<'data, P>,
    OutputSectionPartMap<&'out mut [u8]>,
)> {
    timing_phase!("Split output buffers by group");
    layout
        .group_layouts
        .iter()
        .map(|group| (group, writable_buckets.take_mut(&group.file_sizes)))
        .collect()
}

pub(crate) struct PaddingSlice<'out> {
    pub(crate) slice: &'out mut [u8],
    pub(crate) parent_section_id: Option<OutputSectionId>,
}

#[derive(Default)]
pub(crate) struct PaddingSlices<'out> {
    pub(crate) slices: Vec<PaddingSlice<'out>>,
}

impl PaddingSlices<'_> {
    pub(crate) fn fill_zero(&mut self) {
        verbose_timing_phase!("Fill padding bytes");

        for pslice in &mut self.slices {
            pslice.slice.fill(0);
        }
    }
}

pub(crate) fn split_output_into_sections<'out, 'data, P: Platform>(
    layout: &Layout<'data, P>,
    mut data: &'out mut [u8],
) -> (OutputSectionMap<&'out mut [u8]>, PaddingSlices<'out>) {
    verbose_timing_phase!("Split output by section");

    let mut section_allocations = Vec::with_capacity(layout.section_layouts.len());
    layout.section_layouts.for_each(|id, s| {
        section_allocations.push(SectionAllocation {
            id,
            offset: s.file_offset,
            size: s.file_size,
        });
    });
    section_allocations.sort_by_key(|s| (s.offset, s.offset + s.size));

    let mut padding_slices = PaddingSlices::default();

    // OutputSectionMap is ordered by section ID, which is not the same as output order. We
    // split the output file by output order, putting the relevant parts of the buffer into the
    // map.
    let mut section_data = OutputSectionMap::with_size(section_allocations.len());
    let mut offset = 0;
    let mut prev_primary_id = None;
    for a in section_allocations {
        let Some(padding_size) = a.offset.checked_sub(offset) else {
            panic!(
                "Offsets went backward when splitting output file {offset} to {}",
                a.offset
            );
        };
        let curr_primary_id = layout.output_sections.primary_output_section(a.id);
        padding_slices.slices.push(PaddingSlice {
            slice: data.split_off_mut(..padding_size).unwrap(),
            parent_section_id: prev_primary_id.filter(|prev| *prev == curr_primary_id),
        });

        *section_data.get_mut(a.id) = data.split_off_mut(..a.size).unwrap();
        offset = a.offset + a.size;
        prev_primary_id = Some(curr_primary_id);
    }
    (section_data, padding_slices)
}

/// Splits the writable buffers for each segment further into separate buffers for each alignment.
pub(crate) fn split_buffers_by_alignment<'out, 'data, P: Platform>(
    section_buffers: &'out mut OutputSectionMap<&mut [u8]>,
    layout: &Layout<'data, P>,
) -> OutputSectionPartMap<&'out mut [u8]> {
    layout.section_part_layouts.output_order_map(
        &layout.output_order,
        &layout.output_sections,
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
                        part_id.alignment(&layout.output_sections),
                    )
                })
                .unwrap()
        },
    )
}

fn write_layout<P: Platform>(layout: &Layout<P>, file_system: &impl FileSystem) -> Result {
    let layout_path = linker_layout::layout_path(layout.args().output());
    write_layout_to(layout, &layout_path, file_system)
        .with_context(|| format!("Failed to write layout to `{}`", layout_path.display()))
}

fn write_layout_to<'data, P: Platform>(
    layout: &Layout<'data, P>,
    path: &Path,
    file_system: &impl FileSystem,
) -> Result {
    let mut bytes = Vec::new();
    layout.layout_data().write(&mut bytes)?;
    file_system.write_auxiliary(path, &bytes)
}

/// Copies section bytes from `data` into `out`.
///
/// Small sections are copied with a single `copy_from_slice` call. Large sections may be split
/// into chunks and copied in parallel on multiple threads.
pub(crate) fn copy_section_data(data: &[u8], out: &mut [u8]) {
    /// Threshold size for using parallel copy for section data copying.
    pub(crate) const SECTION_PAR_COPY_SIZE_THRESHOLD: usize = 1_000_000;

    if data.len() >= SECTION_PAR_COPY_SIZE_THRESHOLD {
        let threads = rayon::current_num_threads();
        let chunk_size = (data.len() / threads).max(1);

        data.par_chunks(chunk_size)
            .zip(out.par_chunks_mut(chunk_size))
            .for_each(|(src, dst)| dst.copy_from_slice(src));
    } else {
        out.copy_from_slice(data);
    }
}
