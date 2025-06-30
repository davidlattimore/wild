//! Code for figuring out what input files we need to read then mapping them into memory.

use crate::archive;
use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::archive::EntryMeta;
use crate::args::Args;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::bail;
use crate::error::Context as _;
use crate::error::Error;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::linker_script::LinkerScript;
use colosseum::sync::Arena;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
use foldhash::HashMap;
use foldhash::fast::RandomState;
use memmap2::Mmap;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::ffi::OsStr;
use std::fmt::Display;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) struct InputData<'data> {
    /// These are actual files on disk. We mostly only need to keep these so that we can verify that
    /// they didn't change while we were running.
    pub(crate) files: Vec<&'data InputFile>,

    /// This is like `files`, but archives have been split into their separate parts.
    pub(crate) inputs: Vec<InputBytes<'data>>,

    pub(crate) version_script_data: Option<VersionScriptData<'data>>,
    pub(crate) linker_scripts: Vec<InputLinkerScript<'data>>,

    /// Which files we loaded. The keys aren't relevant anymore, but we keep them to avoid
    /// regenerating the map.
    path_to_load_index: HashMap<PathBuf, FileLoadIndex>,
}

pub(crate) struct InputBytes<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) kind: FileKind,
    pub(crate) data: &'data [u8],
    pub(crate) modifiers: Modifiers,
}

#[derive(Clone, Copy)]
pub(crate) struct VersionScriptData<'data> {
    pub(crate) raw: &'data [u8],
}

/// Identifies an input file. IDs start from 0 which is reserved for our prelude file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FileId(u32);

pub(crate) const PRELUDE_FILE_ID: FileId = FileId::new(0, 0);

pub(crate) struct InputFile {
    pub(crate) filename: PathBuf,

    /// The filename prior to path search. If this is absolute, then `filename` will be the same.
    original_filename: PathBuf,

    pub(crate) kind: FileKind,
    pub(crate) modifiers: Modifiers,

    data: Option<FileData>,
}

pub(crate) struct FileData {
    bytes: Mmap,

    /// The modification timestamp of the input file just before we opened it. We expect our input
    /// files not to change while we're running.
    modification_time: std::time::SystemTime,
}

/// Identifies an input object that may not be a regular file on disk, or may be an entry in an
/// archive.
#[derive(Clone)]
pub(crate) struct InputRef<'data> {
    pub(crate) file: &'data InputFile,
    pub(crate) entry: Option<archive::EntryMeta<'data>>,
}

impl InputFile {
    pub(crate) fn data(&self) -> &[u8] {
        self.data.as_deref().unwrap_or_default()
    }
}

#[derive(Debug)]
struct InputPath {
    /// An absolute path to the file.
    absolute: PathBuf,

    /// The file as specified on the command line. In the case of an argument like -lfoo, this will
    /// be "libfoo.so".
    original: PathBuf,
}

pub(crate) struct InputLinkerScript<'data> {
    pub(crate) script: LinkerScript<'data>,
    pub(crate) input_file: &'data InputFile,
}

struct TemporaryState<'data, 'ch> {
    args: &'data Args,

    /// Mapping from paths to the index in `files` at which we'll place the result.
    path_to_load_index: HashMap<PathBuf, FileLoadIndex>,

    /// The number of OpenFileRequests that we've sent to workers minus the number of responses
    /// we've received. Once this reaches zero, we can shut down.
    outstanding_work_items: u32,

    /// Indexed by FileLoadIndex. As we finish each file, we'll put them into their appropriate
    /// slot. The order in which we finish isn't deterministic, but the indexes at which we place
    /// them are deterministic. Note, the order here is not quite the output order, since files
    /// requested by linker scripts will appear at the end of this Vec, even though those files need
    /// to be put into the final ordering at the place where the linker script was listed. We do it
    /// this way because we don't know how many files a linker script will request until we parse
    /// it. In fact, we don't even know that it will be a linker script until we've actually opened
    /// it.
    files: Vec<Option<LoadedFileState<'data>>>,

    work_recv: &'ch Receiver<OpenFileRequest>,
    response_sender: &'ch Sender<OpenFileResponse<'data>>,
}

enum LoadedFileState<'data> {
    Loaded(&'data InputFile),
    Archive(&'data InputFile, Vec<InputBytes<'data>>),
    ThinArchive(Vec<&'data InputFile>),
    LinkerScript(LoadedLinkerScriptState<'data>),
    Error(Error),
}

struct LoadedLinkerScriptState<'data> {
    /// The indexes of the files requested by the linker script. Some of these indexes may turn out
    /// to have been claimed earlier in the command-line, so we'll only load those that haven't.
    file_indexes: Vec<FileLoadIndex>,

    /// The parsed linker script.
    script: InputLinkerScript<'data>,
}

#[derive(Clone, Copy)]
struct FileLoadIndex(usize);

/// A request for a worker to open the specified input, mmap its contents and identify what type of
/// file it is. If it turns out to be a thin archive, then the referenced files are also loaded.
struct OpenFileRequest {
    file_index: FileLoadIndex,
    paths: InputPath,
    modifiers: Modifiers,
}

struct OpenFileResponse<'data> {
    file_index: FileLoadIndex,
    files: ResponseKind<'data>,
}

enum ResponseKind<'data> {
    Regular(&'data InputFile),
    Archive(&'data InputFile, Vec<InputBytes<'data>>),
    ThinArchiveFiles(Vec<&'data InputFile>),
    LinkerScript(LoadedLinkerScript<'data>),
    Error(Error),
}

struct LoadedLinkerScript<'data> {
    script: InputLinkerScript<'data>,
    extra_inputs: Vec<Input>,
}

impl<'data> InputData<'data> {
    #[tracing::instrument(skip_all, name = "Open input files")]
    pub fn from_args(args: &'data Args, inputs_arena: &'data Arena<InputFile>) -> Result<Self> {
        let version_script_data = args
            .version_script_path
            .as_ref()
            .map(|path| read_version_script(path, inputs_arena))
            .transpose()?;

        let (work_sender, work_recv) = crossbeam_channel::unbounded();
        let (response_sender, response_recv) = crossbeam_channel::unbounded();

        let mut temporary_state = TemporaryState {
            args,
            path_to_load_index: HashMap::with_hasher(RandomState::default()),
            outstanding_work_items: 0,
            files: Vec::new(),
            work_recv: &work_recv,
            response_sender: &response_sender,
        };

        let mut error = None;

        // Open files, mmap them and identify their type from separate threads.
        rayon::scope(|scope| {
            scope.spawn_broadcast(|_, _| {
                while let Ok(request) = work_recv.recv() {
                    let response = process_open_file_request(request, args, inputs_arena);

                    if response_sender.send(response).is_err() {
                        break;
                    }
                }
            });

            if let Err(e) =
                temporary_state.run_main_thread(&work_sender, &response_recv, inputs_arena)
            {
                error = Some(e);
            }

            // Shut down worker threads.
            drop(work_sender);
            drop(response_recv);
        });

        if let Some(e) = error {
            return Err(e);
        }

        let mut inputs = Self {
            files: Vec::new(),
            inputs: Vec::new(),
            linker_scripts: Vec::new(),
            version_script_data,
            path_to_load_index: temporary_state.path_to_load_index,
        };

        inputs.extract_all(&mut temporary_state.files)?;

        args.save_dir.finish(inputs.path_to_load_index.keys())?;

        Ok(inputs)
    }

    /// Checks that the modification timestamp on all our input files hasn't changed since we opened
    /// them. If they were modified while we were running, then we may fail with a SIGBUS if we try
    /// to access part of the file that's no longer there, however if we don't, then we may have
    /// read inconsistent data from the changed object, so we want to fail the link.
    #[tracing::instrument(skip_all, name = "Verify inputs unchanged")]
    pub(crate) fn verify_inputs_unchanged(&self) -> Result {
        self.files.par_iter().try_for_each(|file| {
            let Some(file_data) = &file.data else {
                return Ok(());
            };

            let metadata = std::fs::metadata(&file.filename).with_context(|| {
                format!("Failed to read metadata for `{}`", file.filename.display())
            })?;

            let new_modified = metadata.modified().with_context(|| {
                format!(
                    "Failed to get modification time for `{}`",
                    file.filename.display()
                )
            })?;

            if file_data.modification_time != new_modified {
                bail!(
                    "The file `{}` was changed while we were running",
                    file.filename.display()
                );
            }

            Ok(())
        })
    }

    /// Extract all files and linker scripts from `files`. Extraction order is the same as the order
    /// on the original command-line. This is roughly FileLoadIndex order, except that (a) if a file
    /// is loaded multiple times, it will only appear the first time it's encountered and (b) when a
    /// linker script is loaded, its files appear at the point at which the linker script appeared
    /// on the command-line, even though the FileLoadIndex for files loaded by linker scripts is
    /// later.
    fn extract_all(&mut self, files: &mut [Option<LoadedFileState<'data>>]) -> Result {
        for i in 0..files.len() {
            self.extract_file(FileLoadIndex(i), files)?;
        }

        Ok(())
    }

    fn extract_file(
        &mut self,
        index: FileLoadIndex,
        files: &mut [Option<LoadedFileState<'data>>],
    ) -> Result {
        match core::mem::take(&mut files[index.0]) {
            None => {}
            Some(LoadedFileState::Loaded(input_file)) => {
                self.inputs.push(InputBytes::from_file(input_file));
                self.files.push(input_file);
            }
            Some(LoadedFileState::Archive(input_file, mut parts)) => {
                self.inputs.append(&mut parts);
                self.files.push(input_file);
            }
            Some(LoadedFileState::ThinArchive(mut input_files)) => {
                self.inputs
                    .extend(input_files.iter().map(|file| InputBytes::from_file(file)));
                self.files.append(&mut input_files);
            }
            Some(LoadedFileState::LinkerScript(loaded_linker_script_state)) => {
                self.linker_scripts.push(loaded_linker_script_state.script);

                for i in loaded_linker_script_state.file_indexes {
                    self.extract_file(i, files)?;
                }
            }
            Some(LoadedFileState::Error(error)) => {
                // For now, we just report the first error that we come to.
                return Err(error);
            }
        }

        Ok(())
    }

    pub(crate) fn has_file(&self, name: &'data [u8]) -> bool {
        self.path_to_load_index
            .contains_key(Path::new(OsStr::from_bytes(name)))
    }
}

fn process_linker_script<'data>(
    input_file: &'data InputFile,
    args: &Args,
) -> Result<ResponseKind<'data>> {
    let bytes = input_file.data();
    let script = LinkerScript::parse(bytes, &input_file.filename)?;

    let script_path = std::fs::canonicalize(&input_file.filename)?;
    let directory = script_path.parent().expect("expected an absolute path");

    let mut extra_inputs = Vec::new();

    script.foreach_input(input_file.modifiers, |mut input| {
        input.search_first = Some(directory.to_owned());

        if let (Some(sysroot), InputSpec::File(file)) = (args.sysroot.as_ref(), &mut input.spec) {
            if let Some(new_file) =
                crate::linker_script::maybe_apply_sysroot(&script_path, file, sysroot)
            {
                *file = new_file;
            }
        }

        extra_inputs.push(input);

        Ok(())
    })?;

    Ok(ResponseKind::LinkerScript(LoadedLinkerScript {
        script: InputLinkerScript { script, input_file },
        extra_inputs,
    }))
}

fn process_open_file_request<'data>(
    request: OpenFileRequest,
    args: &Args,
    inputs_arena: &'data Arena<InputFile>,
) -> OpenFileResponse<'data> {
    let files = (|| -> Result<ResponseKind<'data>> {
        let absolute_path = &request.paths.absolute;
        let data = FileData::new(absolute_path.as_path(), args.prepopulate_maps)?;

        let kind = FileKind::identify_bytes(&data.bytes)?;

        let input_file = InputFile {
            filename: absolute_path.to_owned(),
            original_filename: request.paths.original,
            kind,
            modifiers: request.modifiers,
            data: Some(data),
        };

        let input_file = inputs_arena.alloc(input_file);

        Ok(match kind {
            FileKind::Archive => process_archive(input_file)?,
            FileKind::ThinArchive => process_thin_archive(input_file, args, inputs_arena)?,
            FileKind::Text => process_linker_script(input_file, args)?,
            _ => ResponseKind::Regular(input_file),
        })
    })();

    let files = files.unwrap_or_else(ResponseKind::Error);

    OpenFileResponse {
        file_index: request.file_index,
        files,
    }
}

fn process_archive<'data>(input_file: &'data InputFile) -> Result<ResponseKind<'data>> {
    let mut extended_filenames = None;
    let mut outputs = Vec::new();

    for entry in ArchiveIterator::from_archive_bytes(input_file.data())? {
        let entry = entry?;
        match entry {
            ArchiveEntry::Ignored => {}
            ArchiveEntry::Filenames(t) => extended_filenames = Some(t),
            ArchiveEntry::Regular(archive_entry) => {
                let archive_and_member_name = || {
                    format!(
                        "{} @ {}",
                        input_file.filename.to_string_lossy(),
                        archive_entry
                            .identifier(extended_filenames)
                            .as_path()
                            .to_string_lossy()
                    )
                };
                let kind =
                    FileKind::identify_bytes(archive_entry.entry_data).with_context(|| {
                        format!("Failed to parse archive `{}`", archive_and_member_name())
                    })?;
                if kind != FileKind::ElfObject {
                    bail!(
                        "Archive member is not an object `{}`",
                        archive_and_member_name()
                    )
                }
                outputs.push(InputBytes {
                    kind,
                    input: InputRef {
                        file: input_file,
                        entry: Some(EntryMeta {
                            identifier: archive_entry.identifier(extended_filenames),
                            from: archive_entry.data_range(),
                        }),
                    },
                    data: archive_entry.entry_data,
                    modifiers: input_file.modifiers,
                });
            }
            ArchiveEntry::Thin(_) => unreachable!(),
        }
    }

    Ok(ResponseKind::Archive(input_file, outputs))
}

fn process_thin_archive<'data>(
    input_file: &InputFile,
    args: &Args,
    inputs_arena: &'data Arena<InputFile>,
) -> Result<ResponseKind<'data>> {
    let absolute_path = &input_file.filename;
    let parent_path = absolute_path.parent().unwrap();
    let mut extended_filenames = None;
    let mut files = Vec::new();

    for entry in ArchiveIterator::from_archive_bytes(input_file.data())? {
        match entry? {
            ArchiveEntry::Filenames(t) => extended_filenames = Some(t),
            ArchiveEntry::Thin(entry) => {
                let path = entry.identifier(extended_filenames).as_path();
                let entry_path = parent_path.join(path);

                let file_data = FileData::new(&entry_path, args.prepopulate_maps)?;

                let input_file = InputFile {
                    filename: entry_path.clone(),
                    original_filename: entry_path,
                    kind: FileKind::ElfObject,
                    modifiers: Modifiers {
                        archive_semantics: true,
                        ..input_file.modifiers
                    },
                    data: Some(file_data),
                };

                files.push(&*inputs_arena.alloc(input_file));
            }
            _ => {}
        }
    }

    Ok(ResponseKind::ThinArchiveFiles(files))
}

impl<'data, 'ch> TemporaryState<'data, 'ch> {
    fn run_main_thread(
        &mut self,
        work_sender: &Sender<OpenFileRequest>,
        response_recv: &Receiver<OpenFileResponse<'data>>,
        inputs_arena: &'data Arena<InputFile>,
    ) -> Result {
        for input in &self.args.inputs {
            self.load_input(input, work_sender)?;
        }

        while self.outstanding_work_items > 0 {
            while let Some(loaded) = self.try_recv_response(response_recv) {
                let loaded_state = match loaded.files {
                    ResponseKind::Regular(file) => LoadedFileState::Loaded(file),
                    ResponseKind::Archive(file, parts) => LoadedFileState::Archive(file, parts),
                    ResponseKind::ThinArchiveFiles(files) => LoadedFileState::ThinArchive(files),
                    ResponseKind::LinkerScript(loaded) => {
                        let file_indexes = loaded
                            .extra_inputs
                            .into_iter()
                            .map(|input| self.load_input(&input, work_sender))
                            .collect::<Result<Vec<FileLoadIndex>>>()?;

                        LoadedFileState::LinkerScript(LoadedLinkerScriptState {
                            file_indexes,
                            script: loaded.script,
                        })
                    }
                    ResponseKind::Error(error) => LoadedFileState::Error(error),
                };

                self.files[loaded.file_index.0] = Some(loaded_state);

                self.outstanding_work_items -= 1;
            }

            // We've run out of work to receive from workers, so process a work item ourselves. This
            // is mostly here so that we can still function even if there aren't any workers. i.e.
            // if we're running single-threaded.
            if let Ok(request) = self.work_recv.try_recv() {
                let response = process_open_file_request(request, self.args, inputs_arena);
                let _ = self.response_sender.send(response);
            }
        }

        Ok(())
    }

    /// Sends a request to load `input` unless it has already been requested. In either case, return
    /// the index for `input` in our files Vec.
    fn load_input(
        &mut self,
        input: &Input,
        work_sender: &Sender<OpenFileRequest>,
    ) -> Result<FileLoadIndex> {
        let paths = input.path(self.args)?;

        let index = match self.path_to_load_index.entry(paths.absolute.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => *e.get(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let new_index = FileLoadIndex(self.files.len());
                self.files.push(None);

                e.insert(new_index);

                self.outstanding_work_items += 1;

                work_sender.send(OpenFileRequest {
                    file_index: new_index,
                    paths,
                    modifiers: input.modifiers,
                })?;

                new_index
            }
        };

        Ok(index)
    }

    /// Tries to receive a response from `response_recv`, returning None if there isn't any
    /// currently available. If there's no work in the outgoing work queue, then we'll wait a short
    /// time to try to receive a response. This is to avoid busy looping on the main thread when all
    /// the remaining work has been claimed by worker threads. If there is work in the outgoing work
    /// queue, then we don't wait for a response. This ensures that we run as fast as we can when
    /// there are no worker threads.
    fn try_recv_response(
        &self,
        response_recv: &Receiver<OpenFileResponse<'data>>,
    ) -> Option<OpenFileResponse<'data>> {
        if self.work_recv.is_empty() {
            response_recv.recv_timeout(Duration::from_millis(1)).ok()
        } else {
            response_recv.try_recv().ok()
        }
    }
}

fn read_version_script<'data>(
    path: &Path,
    inputs_arena: &'data Arena<InputFile>,
) -> Result<VersionScriptData<'data>> {
    let data = FileData::new(path, false)?;

    let file = inputs_arena.alloc(InputFile {
        filename: path.to_owned(),
        original_filename: path.to_owned(),
        kind: FileKind::Text,
        modifiers: Default::default(),
        data: Some(data),
    });

    Ok(VersionScriptData { raw: file.data() })
}

impl Input {
    fn path(&self, args: &Args) -> Result<InputPath> {
        match &self.spec {
            InputSpec::File(p) => {
                if self.search_first.is_some() || p.parent() == Some(Path::new("")) {
                    if let Some(path) = search_for_file(
                        &args.lib_search_path,
                        self.search_first.as_ref(),
                        p.as_ref(),
                    ) {
                        return Ok(InputPath {
                            absolute: std::path::absolute(path)?,
                            original: p.as_ref().to_owned(),
                        });
                    }
                }
                Ok(InputPath {
                    absolute: p.as_ref().to_owned(),
                    original: p.as_ref().to_owned(),
                })
            }
            InputSpec::Lib(lib_name) => {
                if self.modifiers.allow_shared {
                    let filename = format!("lib{lib_name}.so");
                    if let Some(path) = search_for_file(
                        &args.lib_search_path,
                        self.search_first.as_ref(),
                        &filename,
                    ) {
                        return Ok(InputPath {
                            absolute: std::path::absolute(&path)?,
                            original: PathBuf::from(filename),
                        });
                    }
                }
                let filename = format!("lib{lib_name}.a");
                if let Some(path) =
                    search_for_file(&args.lib_search_path, self.search_first.as_ref(), &filename)
                {
                    return Ok(InputPath {
                        absolute: std::path::absolute(&path)?,
                        original: PathBuf::from(filename),
                    });
                }
                bail!("Couldn't find library `{lib_name}` on library search path");
            }
        }
    }
}

impl FileData {
    pub(crate) fn new(path: &Path, prepopulate_maps: bool) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open input file `{}`", path.display()))?;

        let modification_time = std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .with_context(|| {
                format!("Failed to read file modification time `{}`", path.display())
            })?;

        // Safety: Unfortunately, this is a bit of a compromise. Basically this is only safe if our
        // users manage to avoid editing the input files while we've got them mapped. It'd be great
        // if there were a way to protect against unsoundness when the input files were modified
        // externally, but there isn't - at least on Linux. Not only could the bytes change without
        // notice, but the mapped file could be truncated causing any access to result in a SIGBUS.
        //
        // For our use case, mmap just has too many advantages. There are likely large parts of our
        // input files that we don't need to read, so reading all our input files up front isn't
        // really an option. Reading just the parts we need might be an option, but would add
        // substantial complexity. Also, using mmap means that if the system needs to reclaim
        // memory, it can just release some of our pages.

        let mut mmap_options = memmap2::MmapOptions::new();

        // Prepopulating maps generally slows things down, so is off by default, however it's useful
        // when profiling, since it means that you don't see false positive slowness in the parts of
        // the code that first read a bit of memory.
        if prepopulate_maps {
            mmap_options.populate();
        }

        let bytes = unsafe { mmap_options.map(&file) }
            .with_context(|| format!("Failed to mmap input file `{}`", path.display()))?;

        Ok(FileData {
            bytes,
            modification_time,
        })
    }
}

fn search_for_file(
    lib_search_path: &[Box<Path>],
    search_first: Option<&PathBuf>,
    filename: impl AsRef<Path>,
) -> Option<PathBuf> {
    let filename = filename.as_ref();
    if let Some(search_first) = search_first {
        let path = search_first.join(filename);
        if path.exists() {
            return Some(path);
        }
    }
    for dir in lib_search_path {
        let path = dir.join(filename);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

impl Deref for FileData {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

const FILE_INDEX_BITS: u32 = 8;
pub(crate) const MAX_FILES_PER_GROUP: u32 = 1 << FILE_INDEX_BITS;

impl FileId {
    pub(crate) const fn new(group: u32, file: u32) -> Self {
        Self((group << FILE_INDEX_BITS) | file)
    }

    pub(crate) const fn from_encoded(v: u32) -> Self {
        Self(v)
    }

    pub(crate) fn group(self) -> usize {
        self.0 as usize >> FILE_INDEX_BITS
    }

    pub(crate) fn file(self) -> usize {
        self.0 as usize & ((1 << FILE_INDEX_BITS) - 1)
    }
}

impl std::fmt::Display for InputRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.file.filename.display(), f)?;
        if let Some(entry) = &self.entry {
            std::fmt::Display::fmt(" @ ", f)?;
            std::fmt::Display::fmt(&String::from_utf8_lossy(entry.identifier.as_slice()), f)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for InputRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl std::fmt::Display for FileId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}/{})", self.0, self.group(), self.file())
    }
}

impl<'data> InputRef<'data> {
    pub(crate) fn lib_name(&self) -> &'data [u8] {
        self.file.original_filename.as_os_str().as_encoded_bytes()
    }

    pub(crate) fn has_archive_semantics(&self) -> bool {
        self.entry.is_some() || self.file.modifiers.archive_semantics
    }
}

impl Display for InputBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.input, f)
    }
}

impl<'data> InputBytes<'data> {
    pub(crate) fn from_file(file: &'data crate::input_data::InputFile) -> InputBytes<'data> {
        InputBytes {
            input: InputRef { file, entry: None },
            kind: file.kind,
            data: file.data(),
            modifiers: file.modifiers,
        }
    }
}
