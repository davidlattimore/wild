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
use crate::linker_plugins::LinkerPlugin;
use crate::linker_plugins::LtoInputInfo;
use crate::linker_script::LinkerScript;
use crate::parsing::ParsedInputObject;
use crate::platform::ObjectFile;
use crate::timing_phase;
use crate::verbose_timing_phase;
use colosseum::sync::Arena;
use crossbeam_queue::SegQueue;
use hashbrown::HashMap;
use memmap2::Mmap;
use rayon::Scope;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::fmt::Display;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

pub(crate) struct FileLoader<'data> {
    /// The files that we've loaded so far.
    pub(crate) loaded_files: Vec<&'data InputFile>,

    /// Whether we have at least one input file that is a dynamic object.
    pub(crate) has_dynamic: bool,

    inputs_arena: &'data Arena<InputFile>,
}

#[derive(Default)]
pub(crate) struct LoadedInputs<'data, O: ObjectFile<'data>> {
    /// The results of parsing all the input files and archive entries. We defer checking for
    /// success until later, since otherwise a parse error would mean that the save-dir mechanism
    /// wouldn't capture all the input files.
    pub(crate) objects: Vec<Result<Box<ParsedInputObject<'data, O>>>>,

    pub(crate) linker_scripts: Vec<InputLinkerScript<'data>>,

    pub(crate) lto_objects: Vec<Result<Box<LtoInputInfo<'data>>>>,
}

pub(crate) struct InputBytes<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) kind: FileKind,
    pub(crate) data: &'data [u8],
    pub(crate) modifiers: Modifiers,
}

#[derive(Clone, Copy)]
pub(crate) struct ScriptData<'data> {
    pub(crate) raw: &'data [u8],
}

/// Identifies an input file. IDs start from 0 which is reserved for our prelude file.
#[derive(derive_more::Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[debug("file-{_0}")]
pub(crate) struct FileId(u32);

pub(crate) const PRELUDE_FILE_ID: FileId = FileId::new(0, 0);

#[derive(Debug)]
pub(crate) struct InputFile {
    pub(crate) filename: PathBuf,

    /// The filename prior to path search. If this is absolute, then `filename` will be the same.
    original_filename: PathBuf,

    pub(crate) modifiers: Modifiers,

    data: Option<FileData>,
}

#[derive(Debug)]
pub(crate) struct FileData {
    bytes: Mmap,

    /// The modification timestamp of the input file just before we opened it. We expect our input
    /// files not to change while we're running.
    modification_time: std::time::SystemTime,
}

/// Identifies an input object that may not be a regular file on disk, or may be an entry in an
/// archive.
#[derive(Clone, Copy)]
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

#[derive(Debug)]
pub(crate) struct InputLinkerScript<'data> {
    pub(crate) script: LinkerScript<'data>,
    pub(crate) input_file: &'data InputFile,
}

struct TemporaryState<'data, O: ObjectFile<'data>> {
    args: &'data Args,

    /// Mapping from paths to the index in `files` at which we'll place the result.
    path_to_load_index: Mutex<HashMap<PathBuf, FileLoadIndex>>,

    next_file_load_index: AtomicUsize,

    files: SegQueue<LoadedFile<'data, O>>,

    inputs_arena: &'data Arena<InputFile>,
}

struct LoadedFile<'data, O: ObjectFile<'data>> {
    index: FileLoadIndex,
    state: LoadedFileState<'data, O>,
}

enum LoadedFileState<'data, O: ObjectFile<'data>> {
    Loaded(&'data InputFile, InputRecord<'data, O>),
    Archive(&'data InputFile, Vec<InputRecord<'data, O>>),
    ThinArchive(Vec<&'data InputFile>, Vec<InputRecord<'data, O>>),
    LinkerScript(LoadedLinkerScriptState<'data>),
    Error(Error),
}

enum InputRecord<'data, O: ObjectFile<'data>> {
    Object(Result<Box<ParsedInputObject<'data, O>>>),
    LtoInput(Box<UnclaimedLtoInput<'data>>),
}

struct UnclaimedLtoInput<'data> {
    input_ref: InputRef<'data>,
    file: Arc<std::fs::File>,
    kind: FileKind,
}

struct LoadedLinkerScriptState<'data> {
    /// The indexes of the files requested by the linker script. Some of these indexes may turn out
    /// to have been claimed earlier in the command-line, so we'll only load those that haven't.
    file_indexes: Vec<FileLoadIndex>,

    /// The parsed linker script.
    script: InputLinkerScript<'data>,
}

/// A temporary ID for files that we loaded. Files specified on the command-line will have
/// deterministic values. Other files, e.g. those referenced by thin archives or linker scripts will
/// have non-deterministic values.
#[derive(Clone, Copy)]
struct FileLoadIndex(usize);

/// A request for a worker to open the specified input, mmap its contents and identify what type of
/// file it is. If it turns out to be a thin archive, then the referenced files are also loaded.
struct OpenFileRequest {
    file_index: FileLoadIndex,
    paths: InputPath,
    modifiers: Modifiers,

    /// The file that requested this file be opened. e.g. a linker script. In theory, we could have
    /// a chain of files where linker scripts reference linker scripts, but for simplicity, we only
    /// report the last file in the chain.
    referenced_by: Option<PathBuf>,
}

struct LoadedLinkerScript<'data> {
    script: InputLinkerScript<'data>,
    extra_inputs: Vec<Input>,
}

pub(crate) struct AuxiliaryFiles<'data> {
    pub(crate) version_script_data: Option<ScriptData<'data>>,
    pub(crate) export_list_data: Option<ScriptData<'data>>,
}

impl<'data> AuxiliaryFiles<'data> {
    pub(crate) fn new(args: &'data Args, inputs_arena: &'data Arena<InputFile>) -> Result<Self> {
        let resolve_script_path = |path: &Path| -> PathBuf {
            if path.exists() {
                path.to_owned()
            } else if let Some(found) = search_for_file(&args.lib_search_path, None, path) {
                found
            } else {
                path.to_owned()
            }
        };

        Ok(Self {
            version_script_data: args
                .version_script_path
                .as_ref()
                .map(|path| read_script_data(&resolve_script_path(path), inputs_arena))
                .transpose()?,
            export_list_data: args
                .export_list_path
                .as_ref()
                .map(|path| read_script_data(&resolve_script_path(path), inputs_arena))
                .transpose()?,
        })
    }
}

impl<'data> FileLoader<'data> {
    pub(crate) fn new(inputs_arena: &'data Arena<InputFile>) -> Self {
        Self {
            loaded_files: Vec::new(),
            inputs_arena,
            has_dynamic: false,
        }
    }

    pub(crate) fn load_inputs<O: ObjectFile<'data>>(
        &mut self,
        inputs: &[Input],
        args: &'data Args,
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) -> Result<LoadedInputs<'data, O>> {
        timing_phase!("Open input files");

        let mut path_to_load_index = HashMap::new();

        let mut initial_work = Vec::with_capacity(inputs.len());
        for input in inputs {
            let path = input.path(args)?;
            path_to_load_index
                .entry(path.absolute.clone())
                .or_insert_with(|| {
                    let file_index = FileLoadIndex(initial_work.len());

                    initial_work.push(OpenFileRequest {
                        file_index,
                        paths: path,
                        modifiers: input.modifiers,
                        referenced_by: None,
                    });

                    file_index
                });
        }

        let temporary_state = TemporaryState {
            args,
            path_to_load_index: Mutex::new(path_to_load_index),
            next_file_load_index: AtomicUsize::new(initial_work.len()),
            files: SegQueue::new(),
            inputs_arena: self.inputs_arena,
        };

        // Open files, mmap them and identify their type from separate threads.
        rayon::scope(|scope| {
            initial_work.into_par_iter().for_each(|request| {
                temporary_state.process_and_record_open_file_request(request, scope);
            });
        });

        verbose_timing_phase!("Finalise open input files");

        // Put files into a deterministic order. That order will the order we'd find them if we just
        // processed command-line arguments in order, recursively processing any files that those
        // files pulled in.
        let mut files_by_index = Vec::new();
        files_by_index.resize_with(temporary_state.files.len(), || None);
        for file in temporary_state.files.into_iter() {
            let entry = &mut files_by_index[file.index.0];
            assert!(
                entry.is_none(),
                "Internal error: Multiple files with the same index"
            );
            *entry = Some(file.state);
        }
        self.extract_all(&mut files_by_index, plugin)
    }

    /// Checks that the modification timestamp on all our input files hasn't changed since we opened
    /// them. If they were modified while we were running, then we may fail with a SIGBUS if we try
    /// to access part of the file that's no longer there, however if we don't, then we may have
    /// read inconsistent data from the changed object, so we want to fail the link.
    pub(crate) fn verify_inputs_unchanged(&self) -> Result {
        timing_phase!("Verify inputs unchanged");

        self.loaded_files.par_iter().try_for_each(|file| {
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
    fn extract_all<O: ObjectFile<'data>>(
        &mut self,
        files: &mut [Option<LoadedFileState<'data, O>>],
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) -> Result<LoadedInputs<'data, O>> {
        let mut loaded = LoadedInputs {
            objects: Vec::with_capacity(files.len()),
            linker_scripts: Vec::new(),
            lto_objects: Vec::new(),
        };

        for i in 0..files.len() {
            self.extract_file(FileLoadIndex(i), files, &mut loaded, plugin)?;
        }

        Ok(loaded)
    }

    fn extract_file<O: ObjectFile<'data>>(
        &mut self,
        index: FileLoadIndex,
        files: &mut [Option<LoadedFileState<'data, O>>],
        loaded: &mut LoadedInputs<'data, O>,
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) -> Result {
        match core::mem::take(&mut files[index.0]) {
            None => {}
            Some(LoadedFileState::Loaded(input_file, parse_result)) => {
                if parse_result.is_dynamic_object() {
                    self.has_dynamic = true;
                }
                loaded.add_record(parse_result, plugin);
                self.loaded_files.push(input_file);
            }
            Some(LoadedFileState::Archive(input_file, parsed_parts)) => {
                loaded.add_records(parsed_parts, plugin);
                self.loaded_files.push(input_file);
            }
            Some(LoadedFileState::ThinArchive(mut input_files, parsed_parts)) => {
                loaded.add_records(parsed_parts, plugin);
                self.loaded_files.append(&mut input_files);
            }
            Some(LoadedFileState::LinkerScript(loaded_linker_script_state)) => {
                self.loaded_files
                    .push(loaded_linker_script_state.script.input_file);

                loaded
                    .linker_scripts
                    .push(loaded_linker_script_state.script);

                for i in loaded_linker_script_state.file_indexes {
                    self.extract_file(i, files, loaded, plugin)?;
                }
            }
            Some(LoadedFileState::Error(error)) => {
                // For now, we just report the first error that we come to.
                return Err(error);
            }
        }

        Ok(())
    }
}

fn process_linker_script<'data>(
    input_file: &'data InputFile,
    args: &Args,
) -> Result<LoadedLinkerScript<'data>> {
    let bytes = input_file.data();
    let script = LinkerScript::parse(bytes, &input_file.filename)?;

    let script_path = std::fs::canonicalize(&input_file.filename)?;
    let directory = script_path.parent().expect("expected an absolute path");

    let mut extra_inputs = Vec::new();

    script.foreach_input(input_file.modifiers, |mut input| {
        input.search_first = Some(directory.to_owned());

        if let (Some(sysroot), InputSpec::File(file)) = (args.sysroot.as_ref(), &mut input.spec)
            && let Some(new_file) =
                crate::linker_script::maybe_apply_sysroot(&script_path, file, sysroot)
        {
            *file = new_file;
        }

        extra_inputs.push(input);

        Ok(())
    })?;

    Ok(LoadedLinkerScript {
        script: InputLinkerScript { script, input_file },
        extra_inputs,
    })
}

fn process_archive<'data, O: ObjectFile<'data>>(
    input_file: &'data InputFile,
    file: &Arc<std::fs::File>,
    state: &TemporaryState<'data, O>,
) -> Result<LoadedFileState<'data, O>> {
    let mut outputs = Vec::new();

    for entry in ArchiveIterator::from_archive_bytes(input_file.data())? {
        let entry = entry?;
        match entry {
            ArchiveEntry::Regular(archive_entry) => {
                let input_ref = InputRef {
                    file: input_file,
                    entry: Some(EntryMeta {
                        identifier: archive_entry.ident,
                        start_offset: archive_entry.data_offset,
                        end_offset: archive_entry.data_offset + archive_entry.entry_data.len(),
                    }),
                };

                let kind = FileKind::identify_bytes(input_ref.data())
                    .with_context(|| format!("Failed process input `{input_ref}`"))?;

                outputs.push(state.process_input(input_ref, file, kind)?);
            }
            ArchiveEntry::Thin(_) => unreachable!(),
        }
    }

    Ok(LoadedFileState::Archive(input_file, outputs))
}

fn process_thin_archive<'data, O: ObjectFile<'data>>(
    input_file: &InputFile,
    state: &TemporaryState<'data, O>,
) -> Result<LoadedFileState<'data, O>> {
    let absolute_path = &input_file.filename;
    let parent_path = absolute_path.parent().unwrap();
    let mut files = Vec::new();
    let mut parsed_files = Vec::new();

    for entry in ArchiveIterator::from_archive_bytes(input_file.data())? {
        match entry? {
            ArchiveEntry::Thin(entry) => {
                let path = entry.ident.as_path();
                let entry_path = parent_path.join(path);

                let (file_data, file) = FileData::open(&entry_path, state.args.prepopulate_maps)
                    .with_context(|| {
                        format!(
                            "Failed to open file referenced by thin archive `{}`",
                            input_file.filename.display()
                        )
                    })?;

                let input_file = InputFile {
                    filename: entry_path.clone(),
                    original_filename: entry_path,
                    modifiers: Modifiers {
                        archive_semantics: true,
                        ..input_file.modifiers
                    },
                    data: Some(file_data),
                };

                let input_file = &*state.inputs_arena.alloc(input_file);

                let input_ref = InputRef {
                    file: input_file,
                    entry: None,
                };

                let kind = FileKind::identify_bytes(input_ref.data())
                    .with_context(|| format!("Failed process input `{input_ref}`"))?;

                parsed_files.push(state.process_input(input_ref, &Arc::new(file), kind)?);
                files.push(input_file);
            }
            ArchiveEntry::Regular(_) => {}
        }
    }

    Ok(LoadedFileState::ThinArchive(files, parsed_files))
}

impl<'data, O: ObjectFile<'data>> TemporaryState<'data, O> {
    fn process_and_record_open_file_request<'scope>(
        &'scope self,
        request: OpenFileRequest,
        scope: &Scope<'scope>,
    ) {
        let file_index = request.file_index;
        let loaded_state = self
            .process_open_file_request(request, scope)
            .unwrap_or_else(LoadedFileState::Error);
        self.files.push(LoadedFile {
            index: file_index,
            state: loaded_state,
        });
    }

    fn process_open_file_request<'scope>(
        &'scope self,
        request: OpenFileRequest,
        scope: &Scope<'scope>,
    ) -> Result<LoadedFileState<'data, O>> {
        verbose_timing_phase!("Open file");

        let absolute_path = &request.paths.absolute;
        let result = FileData::open(absolute_path.as_path(), self.args.prepopulate_maps);
        let (data, file) = match request.referenced_by.as_ref() {
            Some(referenced_by) => {
                result.with_context(|| format!("Failed to process `{}`", referenced_by.display()))
            }
            None => result,
        }?;

        let input_file = self.inputs_arena.alloc(InputFile {
            filename: absolute_path.to_owned(),
            original_filename: request.paths.original,
            modifiers: request.modifiers,
            data: Some(data),
        });

        let input_ref = InputRef {
            file: input_file,
            entry: None,
        };

        let data = input_ref.file.data.as_ref().unwrap();
        let kind = FileKind::identify_bytes(&data.bytes)?;

        match kind {
            FileKind::Archive => process_archive(input_file, &Arc::new(file), self),
            FileKind::ThinArchive => process_thin_archive(input_file, self),
            FileKind::Text => {
                let script = process_linker_script(input_file, self.args)?;

                let file_indexes = script
                    .extra_inputs
                    .into_iter()
                    .map(|input| {
                        self.load_input(
                            &input,
                            scope,
                            Some(script.script.input_file.filename.clone()),
                        )
                    })
                    .collect::<Result<Vec<FileLoadIndex>>>()?;

                Ok(LoadedFileState::LinkerScript(LoadedLinkerScriptState {
                    file_indexes,
                    script: script.script,
                }))
            }
            _ => {
                let parsed = self.process_input(input_ref, &Arc::new(file), kind)?;
                Ok(LoadedFileState::Loaded(input_file, parsed))
            }
        }
    }

    /// Sends a request to load `input` unless it has already been requested. In either case, return
    /// the index for `input` in our files Vec.
    fn load_input<'scope>(
        &'scope self,
        input: &Input,
        scope: &Scope<'scope>,
        referenced_by: Option<PathBuf>,
    ) -> Result<FileLoadIndex> {
        let paths = input.path(self.args)?;

        let mut path_to_load_index = self.path_to_load_index.lock().unwrap();

        let index = match path_to_load_index.entry(paths.absolute.clone()) {
            hashbrown::hash_map::Entry::Occupied(e) => *e.get(),
            hashbrown::hash_map::Entry::Vacant(e) => {
                let new_index =
                    FileLoadIndex(self.next_file_load_index.fetch_add(1, Ordering::Relaxed));
                e.insert(new_index);

                drop(path_to_load_index);

                let request = OpenFileRequest {
                    file_index: new_index,
                    paths,
                    modifiers: input.modifiers,
                    referenced_by,
                };

                scope.spawn(|scope| {
                    self.process_and_record_open_file_request(request, scope);
                });

                new_index
            }
        };

        Ok(index)
    }

    fn process_input(
        &self,
        input_ref: InputRef<'data>,
        file: &Arc<std::fs::File>,
        kind: FileKind,
    ) -> Result<InputRecord<'data, O>> {
        let data = input_ref.data();

        // The plugin API docs say to pass files to the plugin before the linker tries to identify
        // the them. Unfortunately the plugin API doesn't provide a fast way to identify files. The
        // plugin API doesn't say anything about thread-safety and although the GCC plugin appears
        // to be threadsafe, the clang plugin definitely isn't. This means that using the API to
        // identify files is much too slow, so we do our own file identification and only pass files
        // to the plugin if we think it can handle them. We can't rely on a plugin only being
        // supplied when actually needed, since GCC seems to pretty much always pass a plugin to the
        // linker.
        if kind.is_compiler_ir() {
            return Ok(InputRecord::LtoInput(Box::new(UnclaimedLtoInput {
                input_ref,
                file: Arc::clone(file),
                kind,
            })));
        }

        if input_ref.is_archive_entry() && kind != FileKind::ElfObject {
            bail!("Unexpected archive member of kind {kind:?}: {input_ref}");
        }

        let input_bytes = InputBytes {
            kind,
            input: input_ref,
            data,
            modifiers: input_ref.file.modifiers,
        };

        let object = ParsedInputObject::new(&input_bytes, self.args);

        Ok(InputRecord::Object(object))
    }
}

fn read_script_data<'data>(
    path: &Path,
    inputs_arena: &'data Arena<InputFile>,
) -> Result<ScriptData<'data>> {
    let data = FileData::new(path, false).context("Failed to read script")?;

    let file = inputs_arena.alloc(InputFile {
        filename: path.to_owned(),
        original_filename: path.to_owned(),
        modifiers: Default::default(),
        data: Some(data),
    });

    Ok(ScriptData { raw: file.data() })
}

impl Input {
    fn path(&self, args: &Args) -> Result<InputPath> {
        match &self.spec {
            InputSpec::File(p) => {
                if self.search_first.is_some()
                    && let Some(path) = search_for_file(
                        &args.lib_search_path,
                        self.search_first.as_ref(),
                        p.as_ref(),
                    )
                {
                    return Ok(InputPath {
                        absolute: std::path::absolute(path)?,
                        original: p.as_ref().to_owned(),
                    });
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
            InputSpec::Search(filename) => {
                if let Some(path) = search_for_file(
                    &args.lib_search_path,
                    self.search_first.as_ref(),
                    filename.as_ref(),
                ) {
                    return Ok(InputPath {
                        absolute: std::path::absolute(&path)?,
                        original: PathBuf::from(filename.as_ref()),
                    });
                }
                bail!("Couldn't find library `{filename}` on library search path");
            }
        }
    }
}

impl FileData {
    pub(crate) fn new(path: &Path, prepopulate_maps: bool) -> Result<Self> {
        Self::open(path, prepopulate_maps).map(|(file_data, _file)| file_data)
    }

    fn open(path: &Path, prepopulate_maps: bool) -> Result<(Self, std::fs::File)> {
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

        Ok((
            FileData {
                bytes,
                modification_time,
            },
            file,
        ))
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

    pub(crate) fn as_u32(self) -> u32 {
        self.0
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

    pub(crate) fn data(&self) -> &'data [u8] {
        if let Some(entry) = &self.entry {
            &self.file.data()[entry.byte_range()]
        } else {
            self.file.data()
        }
    }

    fn is_archive_entry(&self) -> bool {
        self.entry.is_some()
    }
}

impl Display for InputBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.input, f)
    }
}

impl<'data, O: ObjectFile<'data>> LoadedInputs<'data, O> {
    fn add_record(
        &mut self,
        record: InputRecord<'data, O>,
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) {
        match record {
            InputRecord::Object(obj) => self.objects.push(obj),
            InputRecord::LtoInput(obj) => {
                let UnclaimedLtoInput {
                    input_ref,
                    file,
                    kind,
                } = *obj;
                let result = plugin.as_mut()
                    .with_context(|| {
                        format!(
                            "Input file {input_ref} contains {kind}, but linker plugin was not supplied"
                        )
                    })
                    .and_then(|plugin| plugin.process_input(input_ref, &file, kind));
                self.lto_objects.push(result);
            }
        }
    }

    fn add_records(
        &mut self,
        parsed_parts: Vec<InputRecord<'data, O>>,
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) {
        for part in parsed_parts {
            self.add_record(part, plugin);
        }
    }
}

impl<'data, O: ObjectFile<'data>> InputRecord<'data, O> {
    fn is_dynamic_object(&self) -> bool {
        match self {
            InputRecord::Object(Ok(obj)) => obj.is_dynamic(),
            _ => false,
        }
    }
}
