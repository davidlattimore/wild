use crate::OutputKind;
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
use crate::platform;
use crate::platform::Args;
use crate::platform::Platform;
use crate::timing_phase;
use crate::verbose_timing_phase;
use anyhow::anyhow;
use memmap2::MmapOptions;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSlice;
use rayon::slice::ParallelSliceMut;
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
    /// When set, `flush` truncates the file to this many bytes rather
    /// than using the full allocated size. Used by Mach-O where the
    /// writer over-allocates to reserve trailing space for the
    /// codesign blob and then reports the real final size after
    /// signing. When `None`, the full allocation is committed.
    final_size_override: Option<u64>,
}

impl SizedOutput {
    /// Tell `flush` to truncate the output file to exactly
    /// `final_size` bytes instead of the full allocated length.
    /// Idempotent; only the last call matters. Used by the Mach-O
    /// writer once codesign has settled the real end-of-file.
    pub(crate) fn set_final_size(&mut self, final_size: u64) {
        self.final_size_override = Some(final_size);
    }
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
        // SAFETY: `mmap(2)` can't be modelled safely in Rust —
        // POSIX doesn't forbid other processes opening the file and
        // mutating it under us (or truncating, unlinking, etc.),
        // which would race with our `&mut [u8]` view. The stdlib
        // deliberately doesn't offer a safe mmap API for this
        // reason, and every Rust mmap crate (`memmap`, `memmap2`,
        // `mmap-sys`, …) requires `unsafe` at construction.
        //
        // Callers opt in to this risk when they pass
        // `--mmap-output-file`. Our invariants: (1) we create the
        // file fresh via `UnlinkAndReplace` — no pre-existing
        // writers; (2) wild is the only process writing during the
        // link; (3) the mmap is dropped before rename/truncate,
        // removing the alias; (4) `msync(MS_INVALIDATE)` flushes
        // dirty pages before any reader sees the file. Shared with
        // the ELF writer; no Mach-O-specific risk.
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
    pub(crate) fn new(args: &impl platform::Args, output_kind: OutputKind) -> Output {
        let file_write_mode = args
            .common()
            .file_write_mode
            .unwrap_or_else(|| default_file_write_mode(args, output_kind));

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
            creator,
            config: OutputConfig {
                file_write_mode,
                should_write_trace: args.common().write_trace,
                use_mmap: args.common().mmap_output_file,
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

    pub fn write<'data, 'layout, P: Platform>(
        &self,
        layout: &'layout Layout<'data, P>,
        write_fn: impl FnOnce(&mut SizedOutput, &'layout Layout<'data, P>) -> Result,
    ) -> Result {
        timing_phase!("Write output file");
        if layout.args().common().write_layout {
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
fn default_file_write_mode(args: &impl platform::Args, output_kind: OutputKind) -> FileWriteMode {
    if output_kind.is_shared_object() {
        return FileWriteMode::UnlinkAndReplace;
    }

    // On macOS, always unlink-and-replace for executables. AMFI's
    // `UI_WASMAPPEDWRITE` is a sticky vnode flag: once a file has
    // been `PROT_WRITE`-mapped in its lifetime, every future
    // `execve` on that inode is tainted regardless of the current
    // signature. `UpdateInPlaceWithFallback` reuses the inode,
    // which re-triggers the taint on a second-build. A fresh inode
    // via unlink+create is the only reliable reset.
    #[cfg(target_os = "macos")]
    {
        let _ = args;
        return FileWriteMode::UnlinkAndReplace;
    }
    #[cfg(not(target_os = "macos"))]
    {
        if std::fs::metadata(args.output()).is_err() {
            return FileWriteMode::UnlinkAndReplace;
        }
        FileWriteMode::UpdateInPlaceWithFallback
    }
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
            final_size_override: None,
        })
    }

    fn flush(&mut self) -> Result {
        let final_size = self.final_size_override;
        match &mut self.out {
            OutputBuffer::Mmap(mmap) => {
                // On macOS specifically, `msync(MS_SYNC | MS_INVALIDATE)`
                // clears the per-page `wpmapped` taint bit that AMFI
                // checks at `execve`. Without it, a freshly-mapped
                // output file passes `codesign -v` but the kernel
                // SIGKILLs on exec. See LLVM D96164 and radar
                // FB8914231 for the lld-macho precedent. Scope the
                // msync to the real final size when known so the
                // invalidation covers exactly the codesigned range.
                #[cfg(target_os = "macos")]
                {
                    let bytes = final_size
                        .map(|s| (s as usize).min(mmap.len()))
                        .unwrap_or(mmap.len());
                    if bytes > 0 {
                        // SAFETY: FFI call to `msync(2)`. All FFI
                        // crosses the language boundary and is
                        // unsafe by Rust convention; there is no
                        // safe stdlib wrapper. `memmap2::MmapMut::
                        // flush()` internally calls
                        // `msync(MS_SYNC)` but doesn't expose
                        // `MS_INVALIDATE`, which is what the AMFI
                        // workaround requires on macOS.
                        //
                        // Invariants we uphold: `mmap.as_mut_ptr()`
                        // is a valid page-aligned pointer (memmap2
                        // guarantees); `bytes` never exceeds
                        // `mmap.len()` (clamped above); the flags
                        // are a constant `MS_SYNC | MS_INVALIDATE`.
                        let ret = unsafe {
                            libc::msync(
                                mmap.as_mut_ptr() as *mut libc::c_void,
                                bytes,
                                libc::MS_SYNC | libc::MS_INVALIDATE,
                            )
                        };
                        if ret != 0 {
                            return Err(crate::error!(
                                "msync(MS_SYNC|MS_INVALIDATE): {}",
                                std::io::Error::last_os_error()
                            ));
                        }
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    mmap.flush()
                        .with_context(|| format!("msync {}", self.path.display()))?;
                }
            }
            OutputBuffer::InMemory(bytes) => {
                let slice = match final_size {
                    Some(n) => &bytes[..(n as usize).min(bytes.len())],
                    None => &bytes[..],
                };
                self.file
                    .write_all(slice)
                    .with_context(|| format!("Failed to write to {}", self.path.display()))?;
            }
        }

        // Truncate to the real final size if the caller over-
        // allocated (Mach-O reserves trailing space for the codesign
        // blob). Dropping the mmap before `ftruncate` avoids kernel
        // refusals on actively-mapped files.
        if let Some(n) = final_size {
            drop(std::mem::replace(
                &mut self.out,
                OutputBuffer::InMemory(Vec::new()),
            ));
            self.file
                .set_len(n)
                .with_context(|| format!("truncate {}", self.path.display()))?;
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

pub(crate) fn split_output_into_sections<'out, 'data, P: Platform>(
    layout: &Layout<'data, P>,
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

fn write_layout<P: Platform>(layout: &Layout<P>) -> Result {
    let layout_path = linker_layout::layout_path(layout.args().output());
    write_layout_to(layout, &layout_path)
        .with_context(|| format!("Failed to write layout to `{}`", layout_path.display()))
}

fn write_layout_to<'data, P: Platform>(layout: &Layout<'data, P>, path: &Path) -> Result {
    let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
    layout.layout_data().write(&mut file)?;
    Ok(())
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
