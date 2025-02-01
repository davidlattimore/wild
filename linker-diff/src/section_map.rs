use crate::ElfFile64;
use crate::Result;
use anyhow::bail;
use anyhow::Context;
use itertools::Itertools;
use linker_layout::ArchiveEntryInfo;
use object::read::elf::ElfSection64;
use object::LittleEndian;
use object::Object;
use object::ObjectSymbol;
use object::SymbolKind;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt::Display;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

/// A .layout file plus all the files that it references. All data is owned. This struct mostly
/// exists so that `IndexedLayout` has something to borrow from.
pub(crate) struct LayoutAndFiles {
    layout: linker_layout::Layout,

    /// The bytes of each file in the layout.
    files: HashMap<PathBuf, memmap2::Mmap>,
}

impl LayoutAndFiles {
    pub(crate) fn from_base_path(base_path: &Path) -> Result<Option<Self>> {
        let layout_path = linker_layout::layout_path(base_path);

        if !layout_path.exists() {
            return Ok(None);
        }

        let layout_bytes = std::fs::read(layout_path)
            .with_context(|| format!("Failed to read `{}`", base_path.display()))?;

        let layout = linker_layout::Layout::from_bytes(&layout_bytes)?;

        let filenames: HashSet<&PathBuf> = layout.files.iter().map(|file| &file.path).collect();

        let files = filenames
            .into_iter()
            .map(|filename| {
                mmap_file(filename)
                    .with_context(|| format!("Failed to read input file {}", filename.display()))
                    .map(|m| (filename.clone(), m))
            })
            .collect::<Result<HashMap<PathBuf, memmap2::Mmap>>>()?;

        Ok(Some(Self { layout, files }))
    }
}

fn mmap_file(filename: &PathBuf) -> Result<memmap2::Mmap> {
    let file = std::fs::File::open(filename)?;

    // Safety: This is safe so long as the file isn't changed while we're running. We satisfy this
    // by telling our users not to change files while we run. It's lame, but there's no way to
    // create a safe abstraction over mmap on Linux and the performance gains of using mmap are too
    // great to not use it.
    let mmap = unsafe { memmap2::Mmap::map(&file)? };

    Ok(mmap)
}

/// A `.layout` file after we've done some indexing of its contents.
pub(crate) struct IndexedLayout<'data> {
    /// All of the object files that were used as inputs during linking.
    files: Vec<InputFile<'data>>,

    /// Mapping from symbol names to the input section they came from. Only symbols that point to
    /// sections that were copied are present. If multiple symbols with the same name point to
    /// copied sections, then the name is omitted.
    pub(crate) symbol_name_to_section_id: HashMap<&'data [u8], SymbolInfo>,
}

#[derive(Clone, Copy)]
pub(crate) struct SymbolInfo {
    pub(crate) section_id: InputSectionId,
    pub(crate) offset_in_section: u64,
    pub(crate) is_ifunc: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct FunctionInfo<'data> {
    pub(crate) offset_in_section: u64,
    pub(crate) name: &'data [u8],
}

impl<'data> IndexedLayout<'data> {
    pub(crate) fn new(layout_and_files: &'data LayoutAndFiles) -> Result<IndexedLayout<'data>> {
        let mut files = Vec::with_capacity(layout_and_files.layout.files.len());
        let mut symbol_info_by_name = HashMap::new();

        for (file_index, file) in layout_and_files.layout.files.iter().enumerate() {
            let mmap = layout_and_files
                .files
                .get(&file.path)
                .expect("We should have read all the files");

            let object_bytes = if let Some(entry) = file.archive_entry.as_ref() {
                &mmap[entry.range.clone()]
            } else {
                &mmap[..]
            };

            let elf_file = crate::ElfFile64::parse(object_bytes)?;
            let mut functions_by_section = vec![Vec::new(); file.sections.len()];

            for symbol in elf_file.symbols() {
                let Some(section_index) = symbol.section_index() else {
                    continue;
                };

                if !file
                    .sections
                    .get(section_index.0)
                    .is_some_and(|sec| sec.is_some())
                {
                    // This symbol points to a section that we didn't copy. Ignore it.
                }

                let name = symbol.name_bytes()?;

                match symbol_info_by_name.entry(name) {
                    std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
                        // We've got multiple symbols with this name, change the entry to None to
                        // indicate this.
                        occupied_entry.insert(None);
                    }
                    std::collections::hash_map::Entry::Vacant(vacant_entry) => {
                        vacant_entry.insert(Some(SymbolInfo {
                            section_id: InputSectionId {
                                file_index,
                                section_index,
                            },
                            offset_in_section: symbol.address(),
                            is_ifunc: symbol.elf_symbol().st_type() == object::elf::STT_GNU_IFUNC,
                        }));
                    }
                }

                if symbol.kind() == SymbolKind::Text {
                    functions_by_section[section_index.0].push(FunctionInfo {
                        offset_in_section: symbol.address(),
                        name,
                    });
                }
            }

            files.push(InputFile {
                identifier: FileIdentifier {
                    filename: file.path.as_path(),
                    archive_entry: file.archive_entry.as_ref(),
                },
                elf_file,
                sections: file
                    .sections
                    .iter()
                    .zip(functions_by_section)
                    .enumerate()
                    .map(|(section_index, (maybe_sec, mut functions))| {
                        functions.sort_by_key(|f| f.offset_in_section);

                        maybe_sec.as_ref().map(|sec| SectionInfo {
                            addresses: sec.mem_range.clone(),
                            section_id: InputSectionId {
                                file_index,
                                section_index: object::SectionIndex(section_index),
                            },
                            functions,
                        })
                    })
                    .collect(),
            });
        }

        // Drop entries with None (non-unique names).
        let symbol_name_to_section_id: HashMap<&[u8], SymbolInfo> = symbol_info_by_name
            .into_iter()
            .filter_map(|(name, sec)| sec.map(|s| (name, s)))
            .collect();

        let index = IndexedLayout {
            files,
            symbol_name_to_section_id,
        };

        index.validate_no_overlaps()?;

        Ok(index)
    }

    fn validate_no_overlaps(&self) -> Result {
        let mut sections = self
            .files
            .iter()
            .flat_map(|file| file.sections.iter())
            .flatten()
            .collect_vec();

        sections.sort_by_key(|sec| (sec.addresses.start, sec.addresses.end));

        let mut last: Option<&SectionInfo> = None;
        for section in sections {
            if let Some(last) = last {
                if section.addresses.start < last.addresses.end {
                    bail!(
                        "{} overlaps with {}",
                        DisplaySection::new(last, &self.files),
                        DisplaySection::new(section, &self.files)
                    );
                }
            }
            last = Some(section);
        }
        Ok(())
    }

    pub(crate) fn get_section_info(&self, section_id: InputSectionId) -> Option<&SectionInfo> {
        self.files[section_id.file_index].sections[section_id.section_index.0].as_ref()
    }

    pub(crate) fn get_elf_section(
        &self,
        section_id: InputSectionId,
    ) -> Result<ElfSection64<'data, '_, LittleEndian>> {
        Ok(self.files[section_id.file_index]
            .elf_file
            .section_by_index(section_id.section_index)?)
    }

    pub(crate) fn input_file_for_section(&self, section_id: InputSectionId) -> &InputFile {
        &self.files[section_id.file_index]
    }

    pub(crate) fn input_filename_for_section(&self, section_id: InputSectionId) -> &FileIdentifier {
        &self.input_file_for_section(section_id).identifier
    }
}

struct DisplaySection<'data> {
    info: SectionInfo<'data>,
    file: &'data InputFile<'data>,
}

impl<'data> DisplaySection<'data> {
    fn new(info: &SectionInfo<'data>, files: &'data [InputFile]) -> Self {
        Self {
            info: info.clone(),
            file: &files[info.section_id.file_index],
        }
    }
}

impl Display for DisplaySection<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use object::Object as _;
        use object::ObjectSection as _;

        if let Ok(section_name) = self
            .file
            .elf_file
            .section_by_index(self.info.index())
            .and_then(|section| section.name())
        {
            write!(
                f,
                "section `{section_name}` (0x{:x}..0x{:x}) ({})",
                self.info.addresses.start, self.info.addresses.end, self.file.identifier,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct SectionInfo<'data> {
    addresses: Range<u64>,
    section_id: InputSectionId,
    functions: Vec<FunctionInfo<'data>>,
}

pub(crate) struct InputFile<'data> {
    pub(crate) identifier: FileIdentifier<'data>,
    pub(crate) elf_file: ElfFile64<'data>,
    sections: Vec<Option<SectionInfo<'data>>>,
}

pub(crate) struct FileIdentifier<'data> {
    pub(crate) filename: &'data Path,
    pub(crate) archive_entry: Option<&'data ArchiveEntryInfo>,
}

/// Identifies an input section.
#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub(crate) struct InputSectionId {
    pub(crate) file_index: usize,
    pub(crate) section_index: object::SectionIndex,
}

impl SectionInfo<'_> {
    pub(crate) fn index(&self) -> object::SectionIndex {
        self.section_id.section_index
    }

    pub(crate) fn function_at_offset(&self, offset: u64) -> Option<FunctionInfo> {
        match self
            .functions
            .binary_search_by_key(&offset, |f| f.offset_in_section)
        {
            Ok(i) => Some(self.functions[i]),
            Err(0) => None,
            Err(i) => Some(self.functions[i - 1]),
        }
    }
}

impl Display for InputFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.identifier, f)
    }
}

impl Display for FileIdentifier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`", self.filename.display())?;
        if let Some(entry) = self.archive_entry.as_ref() {
            write!(f, " @ `{}`", String::from_utf8_lossy(&entry.identifier))?;
        }
        Ok(())
    }
}
