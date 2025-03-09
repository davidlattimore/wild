//! Code for figuring out what input files we need to read then mapping them into memory.

use crate::archive;
use crate::args::Args;
use crate::args::Input;
use crate::args::InputSpec;
use crate::args::Modifiers;
use crate::error::Result;
use crate::file_kind::FileKind;
use anyhow::Context;
use anyhow::bail;
use memmap2::Mmap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;

pub(crate) struct InputData<'config> {
    pub config: &'config Args,
    pub filenames: HashSet<PathBuf>,
    pub(crate) files: Vec<InputFile>,
    pub(crate) version_script_data: Option<VersionScriptData>,
}

pub(crate) struct VersionScriptData {
    pub(crate) raw: String,
}

/// Identifies an input file. IDs start from 0 which is reserved for our prelude file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileId(u32);

pub(crate) const PRELUDE_FILE_ID: FileId = FileId::new(0, 0);

/// It's convenient for parsed files to know their FileId, however we don't decide their file IDs
/// until we create the groups, which happens after parsing. So we need a placeholder.
pub(crate) const UNINITIALISED_FILE_ID: FileId = FileId::from_encoded(0xffff_ffff);

pub(crate) struct InputFile {
    pub(crate) filename: PathBuf,

    /// The filename prior to path search. If this is absolute, then `filename` will be the same.
    original_filename: PathBuf,
    pub(crate) kind: FileKind,
    pub(crate) modifiers: Modifiers,

    bytes: Option<Mmap>,
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
        self.bytes.as_deref().unwrap_or_default()
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

impl<'config> InputData<'config> {
    #[tracing::instrument(skip_all, name = "Open input files")]
    pub fn from_args(config: &'config Args) -> Result<Self> {
        let files = vec![
            // Our first "file" is a special input that we use internally to emit various symbols
            // and other things that don't come from any actual file.
            InputFile {
                filename: PathBuf::new(),
                original_filename: PathBuf::new(),
                kind: FileKind::Prelude,
                modifiers: Default::default(),
                bytes: None,
            },
        ];

        let version_script_data = config
            .version_script_path
            .as_ref()
            .map(|path| read_version_script(path))
            .transpose()?;

        let mut input_data = Self {
            config,
            filenames: Default::default(),
            files,
            version_script_data,
        };

        for input in &config.inputs {
            input_data.register_input(input, config.sysroot.as_deref())?;
        }

        // Our last "file", similar to the prelude is responsible for internal stuff, but this time
        // at the end.
        input_data.files.push(InputFile {
            filename: PathBuf::new(),
            original_filename: PathBuf::new(),
            kind: FileKind::Epilogue,
            modifiers: Default::default(),
            bytes: None,
        });
        Ok(input_data)
    }

    fn register_input(&mut self, input: &Input, sysroot: Option<&Path>) -> Result {
        let paths = input.path(self.config)?;
        let absolute_path = &paths.absolute;
        if !self.filenames.insert(absolute_path.clone()) {
            // File has already been added.
            return Ok(());
        }

        let bytes = mmap_file(absolute_path.as_path(), self.config.prepopulate_maps)?;

        let kind = FileKind::identify_bytes(&bytes)?;
        if matches!(kind, FileKind::Text) {
            for input in crate::linker_script::linker_script_to_inputs(
                &bytes,
                absolute_path,
                input.modifiers,
                sysroot,
            )? {
                self.register_input(&input, sysroot)?;
            }
            return Ok(());
        }

        let file_info = InputFile {
            filename: absolute_path.to_owned(),
            original_filename: paths.original,
            kind,
            modifiers: input.modifiers,
            bytes: Some(bytes),
        };
        self.files.push(file_info);
        Ok(())
    }
}

fn read_version_script(path: &Path) -> Result<VersionScriptData> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read version script `{}`", path.display()))?;
    Ok(VersionScriptData { raw: data })
}

impl Input {
    fn path(&self, args: &Args) -> Result<InputPath> {
        match &self.spec {
            InputSpec::File(p) => {
                if self.search_first.is_some() {
                    if let Some(absolute) = search_for_file(
                        &args.lib_search_path,
                        self.search_first.as_ref(),
                        p.as_ref(),
                    ) {
                        return Ok(InputPath {
                            absolute,
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
                    if let Some(absolute) = search_for_file(
                        &args.lib_search_path,
                        self.search_first.as_ref(),
                        &filename,
                    ) {
                        return Ok(InputPath {
                            absolute,
                            original: PathBuf::from(filename),
                        });
                    }
                }
                let filename = format!("lib{lib_name}.a");
                if let Some(absolute) =
                    search_for_file(&args.lib_search_path, self.search_first.as_ref(), &filename)
                {
                    return Ok(InputPath {
                        absolute,
                        original: PathBuf::from(filename),
                    });
                }
                bail!("Couldn't find library `{lib_name}` on library search path");
            }
        }
    }
}

pub(crate) fn mmap_file(path: &Path, prepopulate_maps: bool) -> Result<Mmap> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open input file `{}`", path.display()))?;

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

    Ok(bytes)
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
}
