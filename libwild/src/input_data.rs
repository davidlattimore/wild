//! Code for figuring out what input files we need to read then mapping them into memory.

use crate::FileSystem;
use crate::InputFileData;
use crate::archive;
use crate::archive::ArchiveEntry;
use crate::archive::ArchiveIterator;
use crate::archive::EntryMeta;
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
use crate::macho_stub_library::DefinedStubLibrary;
use crate::macho_stub_library::parse_defined_library;
use crate::parsing::ParsedInputObject;
use crate::platform;
use crate::platform::Args;
use crate::platform::Platform;
use crate::timing_phase;
use crate::verbose_timing_phase;
use colosseum::sync::Arena;
use crossbeam_queue::SegQueue;
use hashbrown::HashMap;
use itertools::Itertools as _;
use rayon::Scope;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefIterator;
use rayon::iter::ParallelIterator;
use std::fmt::Display;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

pub(crate) struct FileLoader<'data, F: FileSystem> {
    /// The files that we've loaded so far.
    pub(crate) loaded_files: Vec<&'data InputFile<F::Input>>,

    /// Whether we have at least one input file that is a dynamic object.
    pub(crate) has_dynamic: bool,

    inputs_arena: &'data Arena<InputFile<F::Input>>,

    // File system used for reading and writing of the data.
    file_system: Arc<F>,
}

#[derive(Default)]
pub(crate) struct LoadedInputs<'data, P: Platform> {
    /// The results of parsing all the input files and archive entries. We defer checking for
    /// success until later, since otherwise a parse error would mean that the save-dir mechanism
    /// wouldn't capture all the input files.
    pub(crate) objects: Vec<Result<Box<ParsedInputObject<'data, P>>>>,

    pub(crate) linker_scripts: Vec<InputLinkerScript<'data>>,

    pub(crate) stub_libraries: Vec<LoadedStubLibrary<'data>>,

    pub(crate) lto_objects: Vec<Result<Box<LtoInputInfo<'data>>>>,
}

pub(crate) struct LoadedStubLibrary<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) defined_symbols: DefinedStubLibrary<'data>,
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
#[derive(derive_more::Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[debug("file-{_0}")]
pub(crate) struct FileId(u32);

pub(crate) const PRELUDE_FILE_ID: FileId = FileId::new(0, 0);

#[derive(Debug)]
pub(crate) struct InputFile<D: InputFileData> {
    pub(crate) filename: PathBuf,

    /// The filename prior to path search. If this is absolute, then `filename` will be the same.
    original_filename: PathBuf,

    pub(crate) modifiers: Modifiers,

    data: Option<D>,
}

// A type used for Type-erasure reasons.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InputFileRef<'data> {
    pub(crate) filename: &'data Path,
    original_filename: &'data Path,
    pub(crate) modifiers: Modifiers,
}

impl InputFileRef<'_> {
    #[cfg(test)]
    pub(crate) fn for_testing() -> Self {
        Self {
            filename: Path::new(""),
            original_filename: Path::new(""),
            modifiers: Modifiers::default(),
        }
    }
}

impl<I: InputFileData> InputFile<I> {
    fn data(&self) -> &[u8] {
        self.data.as_ref().map_or(&[], InputFileData::bytes)
    }

    fn as_ref(&self) -> InputFileRef<'_> {
        InputFileRef {
            filename: &self.filename,
            original_filename: &self.original_filename,
            modifiers: self.modifiers,
        }
    }
}

/// Identifies an input object that may not be a regular file on disk, or may be an entry in an
/// archive.
#[derive(Clone, Copy)]
pub(crate) struct InputRef<'data> {
    pub(crate) file: InputFileRef<'data>,
    pub(crate) data: &'data [u8],
    pub(crate) entry: Option<archive::EntryMeta<'data>>,
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
    pub(crate) input_file: InputFileRef<'data>,
    /// Raw bytes of the script file. Used to compute line numbers from `AssertCommand::remainder`.
    pub(crate) script_bytes: &'data [u8],
}

struct TemporaryState<'data, P: Platform, F: FileSystem> {
    args: &'data P::Args,

    /// Mapping from paths to the index in `files` at which we'll place the result.
    path_to_load_index: Mutex<HashMap<PathBuf, FileLoadIndex>>,

    next_file_load_index: AtomicUsize,

    files: SegQueue<LoadedFile<'data, P, F::Input>>,

    inputs_arena: &'data Arena<InputFile<F::Input>>,

    file_system: Arc<F>,
}

struct LoadedFile<'data, P: Platform, I: InputFileData> {
    index: FileLoadIndex,
    state: LoadedFileState<'data, P, I>,
}

enum LoadedFileState<'data, P: Platform, I: InputFileData> {
    Loaded(&'data InputFile<I>, InputRecord<'data, P>),
    Archive(&'data InputFile<I>, Vec<InputRecord<'data, P>>),
    ThinArchive(Vec<&'data InputFile<I>>, Vec<InputRecord<'data, P>>),
    LinkerScript(&'data InputFile<I>, LoadedLinkerScriptState<'data>),
    StubLibrary(&'data InputFile<I>, DefinedStubLibrary<'data>),
    Error(Error),
}

enum InputRecord<'data, P: Platform> {
    Object(Result<Box<ParsedInputObject<'data, P>>>),
    LtoInput(Box<UnclaimedLtoInput<'data>>),
}

struct UnclaimedLtoInput<'data> {
    input_ref: InputRef<'data>,
    file: Option<Arc<std::fs::File>>,
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
    pub(crate) fn new<F: FileSystem>(
        args: &'data impl platform::Args,
        inputs_arena: &'data Arena<InputFile<F::Input>>,
        file_system: &F,
    ) -> Result<Self> {
        let resolve_script_path = |path: &Path| -> PathBuf {
            if file_system.file_type(path).is_ok() {
                path.to_owned()
            } else if let Some(found) =
                search_for_file(file_system, args.lib_search_path(), None, path)
            {
                found
            } else {
                path.to_owned()
            }
        };

        Ok(Self {
            version_script_data: args
                .version_script_path()
                .map(|path| read_script_data(&resolve_script_path(path), inputs_arena, file_system))
                .transpose()?,
            export_list_data: args
                .export_list_path()
                .map(|path| read_script_data(&resolve_script_path(path), inputs_arena, file_system))
                .transpose()?,
        })
    }
}

impl<'data, F: FileSystem> FileLoader<'data, F> {
    pub(crate) fn new(
        inputs_arena: &'data Arena<InputFile<F::Input>>,
        file_system: Arc<F>,
    ) -> Self {
        Self {
            loaded_files: Vec::new(),
            inputs_arena,
            file_system,
            has_dynamic: false,
        }
    }

    pub(crate) fn load_inputs<P: Platform>(
        &mut self,
        inputs: &[Input],
        args: &'data P::Args,
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) -> Result<LoadedInputs<'data, P>> {
        timing_phase!("Open input files");

        let mut path_to_load_index = HashMap::new();

        let mut initial_work = Vec::with_capacity(inputs.len());
        for input in inputs {
            let path = input.path(args, self.file_system.as_ref())?;
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
            file_system: Arc::clone(&self.file_system),
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
        for file in temporary_state.files {
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
            let Some(data) = &file.data else {
                return Ok(());
            };
            if !data
                .verify_unchanged()
                .with_context(|| format!("Failed to verify input `{}`", file.filename.display()))?
            {
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
    fn extract_all<P: Platform>(
        &mut self,
        files: &mut [Option<LoadedFileState<'data, P, F::Input>>],
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) -> Result<LoadedInputs<'data, P>> {
        let mut loaded = LoadedInputs {
            objects: Vec::with_capacity(files.len()),
            linker_scripts: Vec::new(),
            stub_libraries: Vec::new(),
            lto_objects: Vec::new(),
        };

        for i in 0..files.len() {
            self.extract_file(FileLoadIndex(i), files, &mut loaded, plugin)?;
        }

        Ok(loaded)
    }

    fn extract_file<P: Platform>(
        &mut self,
        index: FileLoadIndex,
        files: &mut [Option<LoadedFileState<'data, P, F::Input>>],
        loaded: &mut LoadedInputs<'data, P>,
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
            Some(LoadedFileState::LinkerScript(input_file, loaded_linker_script_state)) => {
                self.loaded_files.push(input_file);

                loaded
                    .linker_scripts
                    .push(loaded_linker_script_state.script);

                for i in loaded_linker_script_state.file_indexes {
                    self.extract_file(i, files, loaded, plugin)?;
                }
            }
            Some(LoadedFileState::StubLibrary(input_file, defined_stub_library)) => {
                self.has_dynamic = true;
                loaded.stub_libraries.push(LoadedStubLibrary {
                    input: InputRef {
                        file: input_file.as_ref(),
                        data: input_file.data(),
                        entry: None,
                    },
                    defined_symbols: defined_stub_library,
                });
                self.loaded_files.push(input_file);
            }
            Some(LoadedFileState::Error(error)) => {
                // For now, we just report the first error that we come to.
                return Err(error);
            }
        }

        Ok(())
    }
}

fn process_linker_script<'data, I: InputFileData>(
    input_file: &'data InputFile<I>,
    args: &impl platform::Args,
    file_system: &impl FileSystem,
) -> Result<LoadedLinkerScript<'data>> {
    let bytes = input_file.data();
    let script = LinkerScript::parse(bytes, &input_file.filename)?;

    let script_path = file_system.canonicalize(&input_file.filename)?;
    let directory = script_path.parent().expect("expected an absolute path");

    let mut extra_inputs = Vec::new();

    script.foreach_input(input_file.modifiers, |mut input| {
        input.search_first = Some(directory.to_owned());

        if let (Some(sysroot), InputSpec::File(file)) = (args.sysroot(), &mut input.spec)
            && let Some(new_file) =
                crate::linker_script::maybe_apply_sysroot(&script_path, file, sysroot)
        {
            *file = new_file;
        }

        extra_inputs.push(input);

        Ok(())
    })?;

    Ok(LoadedLinkerScript {
        script: InputLinkerScript {
            script,
            input_file: input_file.as_ref(),
            script_bytes: bytes,
        },
        extra_inputs,
    })
}

fn process_archive<'data, P: Platform, F: FileSystem>(
    opened: &'data InputFile<F::Input>,
    input_ref: &InputRef<'data>,
    file: Option<&Arc<std::fs::File>>,
    state: &TemporaryState<'data, P, F>,
) -> Result<LoadedFileState<'data, P, F::Input>> {
    let archive_data = input_ref.data();
    let parent_file = input_ref.file;
    let mut members = Vec::new();

    for entry in ArchiveIterator::from_archive_bytes(archive_data)? {
        let entry = entry?;
        match entry {
            ArchiveEntry::Regular(archive_entry) => {
                let start_offset = archive_entry.data_offset;
                let end_offset = archive_entry.data_offset + archive_entry.entry_data.len();
                let member_data = &archive_data[start_offset..end_offset];
                let kind = FileKind::identify_bytes(member_data).with_context(|| {
                    format!(
                        "Failed process input `{}` in archive `{}`",
                        archive_entry.ident.as_path().display(),
                        parent_file.filename.display()
                    )
                })?;
                members.push((start_offset, end_offset, archive_entry.ident, kind));
            }
            ArchiveEntry::Thin(_) => unreachable!(),
        }
    }

    let outputs = members
        .into_par_iter()
        .map(|(start_offset, end_offset, ident, kind)| {
            let member_ref = InputRef {
                file: parent_file,
                data: &archive_data[start_offset..end_offset],
                entry: Some(EntryMeta {
                    identifier: ident,
                    start_offset,
                    end_offset,
                }),
            };
            state.process_input(member_ref, file, kind)
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(LoadedFileState::Archive(opened, outputs))
}

fn process_thin_archive<'data, P: Platform, F: FileSystem>(
    input_file: &'data InputFile<F::Input>,
    state: &TemporaryState<'data, P, F>,
) -> Result<LoadedFileState<'data, P, F::Input>> {
    let absolute_path = &input_file.filename;
    let parent_path = absolute_path.parent().unwrap();
    let modifiers = input_file.modifiers;
    let archive_display = absolute_path.display().to_string();

    // Collect thin-member paths first.
    let mut entry_paths = Vec::new();
    for entry in ArchiveIterator::from_archive_bytes(input_file.data())? {
        match entry? {
            ArchiveEntry::Thin(entry) => {
                entry_paths.push(parent_path.join(entry.ident.as_path()));
            }
            ArchiveEntry::Regular(_) => {}
        }
    }

    let results = entry_paths
        .into_par_iter()
        .map(|entry_path| {
            let (input, file) = state
                .file_system
                .open_input(&entry_path, state.args.common().prepopulate_maps)
                .with_context(|| {
                    format!("Failed to open file referenced by thin archive `{archive_display}`")
                })?;

            let member_file = InputFile {
                filename: entry_path.clone(),
                original_filename: entry_path,
                modifiers: Modifiers {
                    archive_semantics: true,
                    ..modifiers
                },
                data: Some(input),
            };

            let member_file = &*state.inputs_arena.alloc(member_file);

            let input_ref = InputRef {
                file: member_file.as_ref(),
                data: member_file.data(),
                entry: None,
            };

            let kind = FileKind::identify_bytes(input_ref.data())
                .with_context(|| format!("Failed process input `{input_ref}`"))?;

            let parsed = state.process_input(input_ref, file.as_ref(), kind)?;
            Ok::<_, Error>((member_file, parsed))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut files = Vec::with_capacity(results.len());
    let mut parsed_files = Vec::with_capacity(results.len());
    for (member_file, parsed) in results {
        files.push(member_file);
        parsed_files.push(parsed);
    }

    Ok(LoadedFileState::ThinArchive(files, parsed_files))
}

fn process_fat_macho_object<'data, P: Platform, F: FileSystem>(
    file: &'data InputFile<F::Input>,
    input_ref: InputRef<'data>,
    native_file: Option<&Arc<std::fs::File>>,
    state: &TemporaryState<'data, P, F>,
) -> Result<LoadedFileState<'data, P, F::Input>> {
    let data = select_fat_entry_for_cpu_type(input_ref.data(), object::macho::CPU_TYPE_ARM64)
        .with_context(|| format!("Failed to parse FAT object {input_ref}"))?;

    let kind = FileKind::identify_bytes(data).context("Unrecognised entry in FAT file")?;

    let input_ref = InputRef {
        file: input_ref.file,
        data,
        entry: None,
    };

    match kind {
        FileKind::Archive => process_archive(file, &input_ref, native_file, state),
        FileKind::MachOObject | FileKind::MachODylib => {
            let parsed = state.process_input(input_ref, native_file, kind)?;
            Ok(LoadedFileState::Loaded(file, parsed))
        }
        _ => bail!("Unsupported file type {kind} found in FAT object"),
    }
}

impl<'data, P: Platform, F: FileSystem> TemporaryState<'data, P, F> {
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
    ) -> Result<LoadedFileState<'data, P, F::Input>> {
        let absolute_path = &request.paths.absolute;
        verbose_timing_phase!(
            "Open file",
            path = absolute_path.to_string_lossy().to_string()
        );

        let result = self
            .file_system
            .open_input(absolute_path.as_path(), self.args.common().prepopulate_maps);
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
            file: input_file.as_ref(),
            data: input_file.data(),
            entry: None,
        };

        let kind = FileKind::identify_bytes(input_ref.data())
            .with_context(|| format!("Failed to identify {input_ref}"))?;

        match kind {
            FileKind::Archive => process_archive(input_file, &input_ref, file.as_ref(), self),
            FileKind::ThinArchive => process_thin_archive(input_file, self),
            FileKind::Text => {
                let script =
                    process_linker_script(input_file, self.args, self.file_system.as_ref())?;

                let file_indexes = script
                    .extra_inputs
                    .into_iter()
                    .map(|input| {
                        self.load_input(
                            &input,
                            scope,
                            Some(script.script.input_file.filename.to_owned()),
                        )
                    })
                    .collect::<Result<Vec<FileLoadIndex>>>()?;

                Ok(LoadedFileState::LinkerScript(
                    input_file,
                    LoadedLinkerScriptState {
                        file_indexes,
                        script: script.script,
                    },
                ))
            }
            FileKind::MachOStubLibrary => {
                let defined_library = parse_defined_library(str::from_utf8(input_file.data())?)
                    .with_context(|| format!("Failed to process `{}`", absolute_path.display()))?;
                tracing::debug!(file = ?input_file.filename, symbols = defined_library.symbols.len(),
                    weak_symbols = defined_library.weak_symbols.len(), "loaded TBD library");
                Ok(LoadedFileState::StubLibrary(input_file, defined_library))
            }
            FileKind::FatMachOObject => {
                process_fat_macho_object(input_file, input_ref, file.as_ref(), self)
            }
            _ => {
                verbose_timing_phase!(
                    "Process input",
                    path = absolute_path.to_string_lossy().to_string()
                );
                let parsed = self.process_input(input_ref, file.as_ref(), kind)?;
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
        let paths = input.path(self.args, self.file_system.as_ref())?;

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
        file: Option<&Arc<std::fs::File>>,
        kind: FileKind,
    ) -> Result<InputRecord<'data, P>> {
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
                file: file.cloned(),
                kind,
            })));
        }

        if input_ref.is_archive_entry() && !P::is_allowed_in_archive(kind) {
            bail!("Unexpected archive member of kind {kind:?}: {input_ref}");
        }

        let input_bytes = InputBytes {
            kind,
            input: input_ref,
            data,
            modifiers: input_ref.file.modifiers,
        };

        let object = InputRecord::Object(ParsedInputObject::new(&input_bytes, self.args));

        if object.is_dynamic_object() && !input_ref.file.modifiers.allow_shared {
            bail!(
                "Attempted static link of dynamic object {}",
                input_ref.file.filename.display()
            );
        }

        Ok(object)
    }
}

fn select_fat_entry_for_cpu_type(
    data: &[u8],
    target_cpu_type: object::macho::CpuType,
) -> Result<&[u8]> {
    if data.starts_with(&object::macho::FAT_MAGIC_64.to_be_bytes()) {
        select_fat_entry_for_cpu_type_arch::<object::read::macho::FatArch64>(data, target_cpu_type)
    } else {
        select_fat_entry_for_cpu_type_arch::<object::read::macho::FatArch32>(data, target_cpu_type)
    }
}

fn select_fat_entry_for_cpu_type_arch<A: object::read::macho::FatArch>(
    data: &[u8],
    target_cpu_type: object::macho::CpuType,
) -> Result<&[u8]> {
    let parsed = object::read::macho::MachOFatFile::<A>::parse(data)?;

    let fat = parsed
        .arches()
        .iter()
        .find(|arch| arch.cputype() == target_cpu_type)
        .with_context(|| {
            format!(
                "Mach-O fat object didn't contain suitable architecture. Found {}",
                parsed
                    .arches()
                    .iter()
                    .map(|a| a.cpusubtype().to_string())
                    .join(", ")
            )
        })?;

    let offset = fat.offset().into() as usize;
    let size = fat.size().into() as usize;
    Ok(&data[offset..offset + size])
}

fn read_script_data<'data, F: FileSystem>(
    path: &Path,
    inputs_arena: &'data Arena<InputFile<F::Input>>,
    file_system: &F,
) -> Result<ScriptData<'data>> {
    let (input, _) = file_system
        .open_input(path, false)
        .context("Failed to read script")?;

    let file = inputs_arena.alloc(InputFile {
        filename: path.to_owned(),
        original_filename: path.to_owned(),
        modifiers: Default::default(),
        data: Some(input),
    });

    Ok(ScriptData { raw: file.data() })
}

impl Input {
    fn path(&self, args: &impl platform::Args, file_system: &impl FileSystem) -> Result<InputPath> {
        match &self.spec {
            InputSpec::File(p) => {
                if self.search_first.is_some()
                    && let Some(path) = search_for_file(
                        file_system,
                        args.lib_search_path(),
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
                let mut filenames = Vec::new();
                if self.modifiers.allow_shared {
                    filenames.push(PathBuf::from(format!("lib{lib_name}.so")));
                }
                filenames.push(PathBuf::from(format!("lib{lib_name}.a")));
                if let Some((path, filename_index)) = search_for_files(
                    file_system,
                    args.lib_search_path(),
                    self.search_first.as_ref(),
                    &filenames,
                ) {
                    return Ok(InputPath {
                        absolute: std::path::absolute(&path)?,
                        original: filenames[filename_index].clone(),
                    });
                }
                let filename = format!("lib{lib_name}.tbd");
                if let Some(path) = search_for_file(
                    file_system,
                    args.lib_search_path(),
                    self.search_first.as_ref(),
                    &filename,
                ) {
                    return Ok(InputPath {
                        absolute: std::path::absolute(&path)?,
                        original: PathBuf::from(filename),
                    });
                }
                bail!("Couldn't find library `{lib_name}` on library search path");
            }
            InputSpec::Search(filename) => {
                if let Some(path) = search_for_file(
                    file_system,
                    args.lib_search_path(),
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

fn search_for_file(
    file_system: &impl FileSystem,
    lib_search_path: &[Box<Path>],
    search_first: Option<&PathBuf>,
    filename: impl AsRef<Path>,
) -> Option<PathBuf> {
    let filename = filename.as_ref();
    if let Some(search_first) = search_first {
        let path = search_first.join(filename);
        if file_system.file_type(&path).is_ok() {
            return Some(path);
        }
    }
    for dir in lib_search_path {
        let path = dir.join(filename);
        if file_system.file_type(&path).is_ok() {
            return Some(path);
        }
    }
    None
}

fn search_for_files(
    file_system: &impl FileSystem,
    lib_search_path: &[Box<Path>],
    search_first: Option<&PathBuf>,
    filenames: &[PathBuf],
) -> Option<(PathBuf, usize)> {
    let search_dir = |dir: &Path| {
        filenames.iter().enumerate().find_map(|(index, filename)| {
            let path = dir.join(filename);
            file_system
                .file_type(&path)
                .is_ok()
                .then_some((path, index))
        })
    };

    search_first
        .and_then(|dir| search_dir(dir))
        .or_else(|| lib_search_path.iter().find_map(|dir| search_dir(dir)))
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
        self.data
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

impl<'data, P: Platform> LoadedInputs<'data, P> {
    fn add_record(
        &mut self,
        record: InputRecord<'data, P>,
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
                let plugin_result = plugin.as_mut()
                    .with_context(|| {
                        format!(
                            "Input file {input_ref} contains {kind}, but linker plugin was not supplied"
                        )
                    })
                    .and_then(|plugin| {
                        let file = file
                            .as_deref()
                            .context("Linker plugins require a native filesystem input")?;
                        plugin.process_input(input_ref, file, kind)
                    });
                match plugin_result {
                    Ok(Some(info)) => self.lto_objects.push(Ok(info)),
                    Ok(None) => {} // Skipped, e.g. unclaimed IR member inside an archive
                    Err(e) => self.lto_objects.push(Err(e)),
                }
            }
        }
    }

    fn add_records(
        &mut self,
        parsed_parts: Vec<InputRecord<'data, P>>,
        plugin: &mut Option<LinkerPlugin<'data>>,
    ) {
        for part in parsed_parts {
            self.add_record(part, plugin);
        }
    }
}

impl<'data, P: Platform> InputRecord<'data, P> {
    fn is_dynamic_object(&self) -> bool {
        match self {
            InputRecord::Object(Ok(obj)) => obj.is_dynamic(),
            _ => false,
        }
    }
}
