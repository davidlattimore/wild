//! Filesystem abstraction used by the linker.
//!
//! The main output is exposed as a sized random-access byte buffer because linker writers fill
//! disjoint regions in parallel. Auxiliary outputs are written as complete byte slices.

use crate::error::Context as _;
use crate::error::Result;
#[cfg(not(target_family = "wasm"))]
use memmap2::Mmap;
use memmap2::MmapOptions;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Write as _;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReplacementMode {
    /// The existing output file, if any, will be unlinked (deleted) and a new file with the same
    /// name put in its place. Any hard links to the file will not be affected.
    UnlinkAndReplace,

    /// The existing output file, if any, will be edited in-place. Any hard links to the file will
    /// update accordingly. If the file is locked due to currently being executed, then our write
    /// will fail.
    UpdateInPlace,

    /// As for `UpdateInPlace`, but if we get an error opening the file for write, fallback to
    /// unlinking and replacing.
    UpdateInPlaceWithFallback,
}

#[derive(Debug, Clone, Copy)]
pub enum FileWriteMode {
    Mmap,
    BufferThenWrite,
}

#[derive(Debug, Clone, Copy)]
pub struct OutputOptions {
    pub size: u64,
    pub file_replacement_mode: FileReplacementMode,
    pub write_mode: Option<FileWriteMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Other,
}

/// An opened linker input. Implementations own the storage returned by [`InputFile::bytes`].
pub trait InputFileData: Send + Sync + std::fmt::Debug {
    fn bytes(&self) -> &[u8];

    /// Returns whether the input still has the same identity as when it was opened.
    fn verify_unchanged(&self) -> std::io::Result<bool> {
        Ok(true)
    }
}

/// A sized, random-access linker output.
pub trait OutputFileData: Send {
    /// Returns the complete output buffer for reading.
    fn bytes(&self) -> &[u8];

    /// Returns the output buffer for random-access writing.
    fn bytes_mut(&mut self) -> &mut [u8];

    /// Persist the bytes and apply final file attributes.
    fn finish(self) -> Result;

    /// Invalidate any OS caches that may have observed partially written output.
    fn invalidate(&mut self, _len: usize) {}
}

/// Filesystem services needed by the core linker.
///
/// # Examples
///
/// ```
/// use libwild::{FileSystem, FileType, InputFileData, Linker, OutputFileData, OutputOptions};
/// use object::write::{Object, StandardSection, Symbol, SymbolSection};
/// use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
/// use std::collections::HashMap;
/// use std::fs::File;
/// use std::mem;
/// use std::path::{Path, PathBuf};
/// use std::sync::{Arc, Mutex};
///
/// // A small in-memory filesystem backed by a dictionary of path -> contents.
/// #[derive(Clone, Default)]
/// pub(crate) struct InMemoryFileSystem {
///     pub(crate) files: Arc<Mutex<HashMap<PathBuf, Vec<u8>>>>,
/// }
///
/// #[derive(Debug)]
/// struct Input(Vec<u8>);
///
/// impl InputFileData for Input {
///     fn bytes(&self) -> &[u8] {
///         &self.0
///     }
/// }
///
/// struct Output {
///     path: PathBuf,
///     bytes: Vec<u8>,
///     files: Arc<Mutex<HashMap<PathBuf, Vec<u8>>>>,
/// }
///
/// impl OutputFileData for Output {
///     fn bytes(&self) -> &[u8] {
///         &self.bytes
///     }
///
///     fn bytes_mut(&mut self) -> &mut [u8] {
///         &mut self.bytes
///     }
///
///     fn finish(mut self) -> libwild::error::Result {
///         let data = mem::take(&mut self.bytes);
///         self.files.lock().unwrap().insert(self.path.clone(), data);
///         Ok(())
///     }
/// }
///
/// impl FileSystem for InMemoryFileSystem {
///     type Input = Input;
///     type Output = Output;
///
///     fn open_input(
///         &self,
///         path: &Path,
///         _prepopulate_maps: bool,
///     ) -> libwild::error::Result<(Self::Input, Option<Arc<File>>)> {
///         let bytes = self
///             .files
///             .lock()
///             .unwrap()
///             .get(&path.to_path_buf())
///             .cloned()
///             .ok_or_else(|| libwild::error!("No such in-memory file: {}", path.display()))?;
///         Ok((Input(bytes), None))
///     }
///
///     fn file_type(&self, path: &Path) -> std::io::Result<FileType> {
///         if self.files.lock().unwrap().contains_key(&path.to_path_buf()) {
///             Ok(FileType::File)
///         } else {
///             Err(std::io::Error::new(
///                 std::io::ErrorKind::NotFound,
///                 "no such in-memory file",
///             ))
///         }
///     }
///
///     fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
///         Ok(path.to_path_buf())
///     }
///
///     fn rename_file(&self, path: &Path, new_path: &Path) -> std::io::Result<()> {
///         let mut guard = self.files.lock().unwrap();
///         let Some(data) = guard.remove(&path.to_path_buf()) else {
///             return Err(std::io::Error::new(
///                 std::io::ErrorKind::NotFound,
///                 "no such in-memory file",
///             ));
///         };
///         guard.insert(new_path.to_path_buf(), data);
///
///         Ok(())
///     }
///
///     fn remove_file(&self, path: &Path) -> std::io::Result<()> {
///         self.files
///             .lock()
///             .unwrap()
///             .remove(&path.to_path_buf())
///             .map(|_| ())
///             .ok_or_else(|| {
///                 std::io::Error::new(std::io::ErrorKind::NotFound, "no such in-memory file")
///             })
///     }
///
///     fn create_output(
///         &self,
///         path: Arc<Path>,
///         options: OutputOptions,
///     ) -> libwild::error::Result<Self::Output> {
///         let size = usize::try_from(options.size)
///             .map_err(|_| libwild::error!("output is too large for this platform"))?;
///         Ok(Output {
///             path: path.to_path_buf(),
///             bytes: vec![0; size],
///             files: Arc::clone(&self.files),
///         })
///     }
///
///     fn write_auxiliary(&self, path: &Path, bytes: &[u8]) -> libwild::error::Result {
///         self.files
///             .lock()
///             .unwrap()
///             .insert(path.to_path_buf(), bytes.to_vec());
///         Ok(())
///     }
/// }
///
/// fn create_main_object() -> object::write::Result<Vec<u8>> {
///     let mut object = Object::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
///     let data = object.section_id(StandardSection::Data);
///     let symbol = object.add_symbol(Symbol {
///         name: b"foo".to_vec(),
///         value: 0,
///         size: 0,
///         kind: SymbolKind::Data,
///         scope: SymbolScope::Dynamic,
///         weak: false,
///         section: SymbolSection::Undefined,
///         flags: SymbolFlags::None,
///     });
///     object.add_symbol_data(symbol, data, &42_u32.to_le_bytes(), 4);
///     object.write()
/// }
///
/// fn run() -> libwild::error::Result {
///     let fs = InMemoryFileSystem::default();
///
///     fs.files
///         .lock()
///         .unwrap()
///         .insert(PathBuf::from("main.o"), create_main_object()?);
///
///     let arguments = [
///         "wild",
///         "-m",
///         "elf_x86_64",
///         "-shared",
///         "main.o",
///         "-o",
///         "libx.so",
///     ];
///     let get_arguments = || arguments.into_iter();
///     let mut args = libwild::Args::new(get_arguments)?;
///     args.parse(get_arguments)?;
///
///     let linker = Linker::with_file_system(fs.clone());
///     linker.run(&args)?;
///
///     let output = fs
///         .files
///         .lock()
///         .unwrap()
///         .get(Path::new("libx.so"))
///         .cloned()
///         .ok_or_else(|| libwild::error!("linker did not create libx.so"))?;
///     // std::fs::write("libx.so", &output)?;
///     Ok(())
/// }
/// ```
pub trait FileSystem: Send + Sync + 'static {
    type Input: InputFileData;
    type Output: OutputFileData;

    /// Opens an input and optionally requests that its pages be populated in advance.
    fn open_input(
        &self,
        path: &Path,
        prepopulate_maps: bool,
    ) -> Result<(Self::Input, Option<Arc<File>>)>;

    /// Returns the type of the file at `path`.
    fn file_type(&self, path: &Path) -> Result<FileType>;

    /// Resolves symbolic links and returns the canonical absolute path.
    fn canonicalize(&self, path: &Path) -> Result<PathBuf>;

    /// Removes a file.
    fn remove_file(&self, path: &Path) -> Result<()>;

    /// Rename an existing file to a new path.
    fn rename_file(&self, path: &Path, new_path: &Path) -> Result<()>;

    /// Creates the sized random-access output.
    fn create_output(&self, path: Arc<Path>, options: OutputOptions) -> Result<Self::Output>;

    /// Writes a complete auxiliary output.
    fn write_auxiliary(&self, path: &Path, bytes: &[u8]) -> Result;
}

/// The normal host operating-system filesystem.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsFileSystem;

impl OsFileSystem {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
struct OsInputBytes(Mmap);

#[cfg(target_family = "wasm")]
struct OsInputBytes(Vec<u8>);

#[cfg(target_family = "wasm")]
impl std::fmt::Debug for OsInputBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FileBytes").finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct OsInputFile {
    bytes: OsInputBytes,
    path: PathBuf,
    /// The modification timestamp of the input file just before we opened it. We expect our input
    /// files not to change while we're running.
    modification_time: std::time::SystemTime,
}

impl Deref for OsInputBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl InputFileData for OsInputFile {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn verify_unchanged(&self) -> std::io::Result<bool> {
        Ok(std::fs::metadata(&self.path)?.modified()? == self.modification_time)
    }
}

enum OsOutputBuffer {
    Mmap(memmap2::MmapMut),
    InMemory(Vec<u8>),
}

pub struct OsOutputFile {
    file: File,
    buffer: OsOutputBuffer,
    path: Arc<Path>,
}

impl OutputFileData for OsOutputFile {
    fn bytes(&self) -> &[u8] {
        match &self.buffer {
            OsOutputBuffer::Mmap(mmap) => mmap,
            OsOutputBuffer::InMemory(bytes) => bytes,
        }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        match &mut self.buffer {
            OsOutputBuffer::Mmap(mmap) => mmap,
            OsOutputBuffer::InMemory(bytes) => bytes,
        }
    }

    fn finish(mut self) -> Result {
        if let OsOutputBuffer::InMemory(bytes) = &self.buffer {
            self.file
                .write_all(bytes)
                .with_context(|| format!("Failed to write to {}", self.path.display()))?;
        }

        // Making the file executable is best-effort only. For example if we're writing to a pipe or
        // something, it isn't going to work and that's OK.
        let _ = make_executable(&self.file);

        Ok(())
    }

    fn invalidate(&mut self, len: usize) {
        #[cfg(target_os = "macos")]
        if let OsOutputBuffer::Mmap(output) = &mut self.buffer {
            unsafe {
                libc::msync(output.as_mut_ptr().cast(), len, libc::MS_INVALIDATE);
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = len;
    }
}

impl FileSystem for OsFileSystem {
    type Input = OsInputFile;
    type Output = OsOutputFile;

    fn open_input(
        &self,
        path: &Path,
        #[allow(unused_variables)] prepopulate_maps: bool,
    ) -> Result<(Self::Input, Option<Arc<File>>)> {
        #[allow(unused_mut)]
        let mut file = File::open(path)
            .with_context(|| format!("Failed to open input file `{}`", path.display()))?;

        let modification_time = file
            .metadata()
            .and_then(|meta| meta.modified())
            .with_context(|| {
                format!("Failed to read file modification time `{}`", path.display())
            })?;

        #[cfg(not(target_family = "wasm"))]
        let bytes = {
            // Safety: Unfortunately, this is a bit of a compromise. Basically this is only safe if
            // our users manage to avoid editing the input files while we've got them
            // mapped. It'd be great if there were a way to protect against unsoundness
            // when the input files were modified externally, but there isn't - at least
            // on Linux. Not only could the bytes change without notice, but the mapped
            // file could be truncated causing any access to result in a SIGBUS.
            //
            // For our use case, mmap just has too many advantages. There are likely large parts of
            // our input files that we don't need to read, so reading all our input
            // files up front isn't really an option. Reading just the parts we need
            // might be an option, but would add substantial complexity. Also, using
            // mmap means that if the system needs to reclaim memory, it can just
            // release some of our pages.

            let mut mmap_options = memmap2::MmapOptions::new();

            // Prepopulating maps generally slows things down, so is off by default, however it's
            // useful when profiling, since it means that you don't see false positive
            // slowness in the parts of the code that first read a bit of memory.
            if prepopulate_maps {
                mmap_options.populate();
            }

            let bytes = unsafe { mmap_options.map(&file) }
                .with_context(|| format!("Failed to mmap input file `{}`", path.display()))?;

            OsInputBytes(bytes)
        };

        #[cfg(target_family = "wasm")]
        let bytes = {
            use std::io::Read as _;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .with_context(|| format!("Failed to read file `{}`", path.display()))?;
            OsInputBytes(bytes)
        };

        Ok((
            OsInputFile {
                bytes,
                path: path.to_owned(),
                modification_time,
            },
            Some(Arc::new(file)),
        ))
    }

    fn file_type(&self, path: &Path) -> Result<FileType> {
        let ty = std::fs::metadata(path)?.file_type();
        Ok(if ty.is_file() {
            FileType::File
        } else if ty.is_dir() {
            FileType::Directory
        } else {
            FileType::Other
        })
    }

    fn canonicalize(&self, path: &Path) -> Result<PathBuf> {
        std::fs::canonicalize(path)
    }

    fn remove_file(&self, path: &Path) -> Result<()> {
        std::fs::remove_file(path)
    }

    fn rename_file(&self, path: &Path, new_path: &Path) -> Result<()> {
        std::fs::rename(path, new_path)
    }

    fn create_output(&self, path: Arc<Path>, options: OutputOptions) -> Result<Self::Output> {
        let mut open_options = std::fs::OpenOptions::new();

        match options.file_replacement_mode {
            FileReplacementMode::UnlinkAndReplace => {
                open_options.truncate(true);
            }
            FileReplacementMode::UpdateInPlace | FileReplacementMode::UpdateInPlaceWithFallback => {
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
                        options.file_replacement_mode,
                        FileReplacementMode::UpdateInPlaceWithFallback
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

        let file_write_mode = options
            .write_mode
            .unwrap_or_else(|| default_file_write_mode_for_file(&file));

        let buffer = match file_write_mode {
            FileWriteMode::Mmap => {
                // For some types of output file (e.g. character devices) we can't mmap, so we try
                // to mmap the file and if it fails, fall back to non-mmapped output.
                if file.set_len(options.size).is_ok() {
                    match unsafe { MmapOptions::new().map_mut(&file) } {
                        Ok(mmap) => OsOutputBuffer::Mmap(mmap),
                        Err(_) => OsOutputBuffer::InMemory(vec![0; options.size as usize]),
                    }
                } else {
                    OsOutputBuffer::InMemory(vec![0; options.size as usize])
                }
            }
            FileWriteMode::BufferThenWrite => {
                // Try to set the length of the file. We ignore failures here because it's expected
                // to fail for some types of files, e.g. /dev/null. If there's actually a problem
                // writing to the file, we'll discover that when we go to write the content later
                // on.
                let _ = file.set_len(options.size);
                OsOutputBuffer::InMemory(vec![0; options.size as usize])
            }
        };

        Ok(OsOutputFile { file, buffer, path })
    }

    fn write_auxiliary(&self, path: &Path, bytes: &[u8]) -> Result {
        let file = File::create(path)?;
        (&file).write_all(bytes)?;
        Ok(())
    }
}

fn default_file_write_mode_for_file(file: &std::fs::File) -> FileWriteMode {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        match nix::sys::statfs::fstatfs(file)
            .map(|stat| stat.filesystem_type())
            .ok()
        {
            // Multi-threaded write performance with BTRFS is terrible. It's substantially faster to
            // just buffer it all in memory then write it afterwards.
            Some(nix::sys::statfs::BTRFS_SUPER_MAGIC) => FileWriteMode::BufferThenWrite,
            // vfat isn't quite as bad as BTRFS in this regard, but it's still at least 4-10% faster
            // if we avoid mmap.
            Some(nix::sys::statfs::MSDOS_SUPER_MAGIC) => FileWriteMode::BufferThenWrite,
            _ => FileWriteMode::Mmap,
        }
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        let _ = file;
        FileWriteMode::Mmap
    }
}

/// Make the the supplied file executable by adding execute permissions for all users that have read
/// permissions. On non-Unix platforms, this is a no-op.
pub fn make_executable(_file: &File) -> Result {
    #[cfg(unix)]
    {
        use std::os::unix::prelude::PermissionsExt;
        let mut permissions = _file.metadata()?.permissions();
        let mut mode = PermissionsExt::mode(&permissions);
        // Set execute permission wherever we currently have read permission.
        mode = mode | ((mode & 0o444) >> 2);
        PermissionsExt::set_mode(&mut permissions, mode);
        _file.set_permissions(permissions)?;
    }
    Ok(())
}

pub(crate) fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        std::path::Path::new(OsStr::from_bytes(bytes)).to_path_buf()
    }

    #[cfg(target_os = "wasi")]
    {
        use std::ffi::OsStr;
        use std::os::wasi::ffi::OsStrExt as _;
        std::path::Path::new(OsStr::from_bytes(bytes)).to_path_buf()
    }

    #[cfg(not(any(unix, target_os = "wasi")))]
    {
        let path = std::str::from_utf8(bytes).expect("Invalid UTF-8 in archive path name");
        PathBuf::from(path)
    }
}
