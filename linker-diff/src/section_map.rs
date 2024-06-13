use crate::ElfFile64;
use crate::Result;
use anyhow::bail;
use anyhow::Context;
use linker_layout::ArchiveEntryInfo;
use std::fmt::Display;
use std::io::Read;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

pub(crate) struct LayoutAndFiles {
    layout: linker_layout::Layout,
    /// The bytes of each file in the layout.
    files: Vec<Vec<u8>>,
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
        let files = layout
            .files
            .iter()
            .map(read_object_bytes)
            .collect::<Result<Vec<Vec<u8>>>>()?;
        Ok(Some(Self { layout, files }))
    }
}

pub(crate) struct IndexedLayout<'data> {
    files: Vec<InputFile<'data>>,
    sections: Vec<SectionInfo>,
}

impl<'data> IndexedLayout<'data> {
    pub(crate) fn new(layout_and_files: &'data LayoutAndFiles) -> Result<IndexedLayout> {
        let mut files = Vec::with_capacity(layout_and_files.layout.files.len());
        let mut sections = Vec::new();
        for ((file_index, file), object_bytes) in layout_and_files
            .layout
            .files
            .iter()
            .enumerate()
            .zip(&layout_and_files.files)
        {
            files.push(InputFile {
                filename: file.path.as_path(),
                archive_entry: file.archive_entry.as_ref(),
                elf_file: crate::ElfFile64::parse(object_bytes)?,
            });
            sections.extend(file.sections.iter().enumerate().filter_map(
                |(section_index, maybe_sec)| {
                    maybe_sec.as_ref().map(|sec| SectionInfo {
                        addresses: sec.mem_range.clone(),
                        file_index,
                        section_index,
                    })
                },
            ));
        }
        sections.sort_by_key(|sec| (sec.addresses.start, sec.addresses.end));
        let index = IndexedLayout { files, sections };
        index.validate_no_overlaps()?;
        Ok(index)
    }

    pub(crate) fn address_range(&self) -> Option<Range<u64>> {
        let min = self.sections.iter().map(|s| s.addresses.start).min()?;
        let max = self.sections.iter().map(|s| s.addresses.end).max()?;
        Some(min..max)
    }

    /// Returns the first input file, if any that we can determine was mapped into the supplied
    /// address range.
    pub(crate) fn file_in_range(&self, addresses: Range<u64>) -> Option<&InputFile> {
        let mut i = self
            .sections
            .binary_search_by_key(&addresses.start, |sec| sec.addresses.start)
            .unwrap_or_else(|p| p);
        while let Some(section) = self.sections.get(i) {
            if section.addresses.start >= addresses.end {
                return None;
            }
            if addresses.end <= section.addresses.start {
                i += 1;
            } else {
                return Some(&self.files[section.file_index]);
            }
        }
        None
    }

    pub(crate) fn resolve_address(&self, address: u64) -> Option<InputResolution> {
        let i = self
            .sections
            .binary_search_by_key(&address, |sec| sec.addresses.end)
            .unwrap_or_else(|p| p);
        let section = self.sections.get(i)?;
        if !section.addresses.contains(&address) {
            return None;
        }
        Some(InputResolution {
            file: &self.files[section.file_index],
            section,
            offset_in_section: address - section.addresses.start,
        })
    }

    fn validate_no_overlaps(&self) -> Result {
        let mut last: Option<&SectionInfo> = None;
        for section in &self.sections {
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
}

struct DisplaySection<'data> {
    info: SectionInfo,
    file: &'data InputFile<'data>,
}

impl<'data> DisplaySection<'data> {
    fn new(info: &SectionInfo, files: &'data [InputFile]) -> Self {
        Self {
            info: info.clone(),
            file: &files[info.section_index],
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
                "section `{section_name}` (0x{:x}..0x{:x})",
                self.info.addresses.start, self.info.addresses.end
            )?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct SectionInfo {
    addresses: Range<u64>,
    file_index: usize,
    section_index: usize,
}

pub(crate) struct InputFile<'data> {
    filename: &'data Path,
    archive_entry: Option<&'data ArchiveEntryInfo>,
    pub(crate) elf_file: ElfFile64<'data>,
}

pub(crate) struct InputResolution<'obj> {
    pub(crate) file: &'obj InputFile<'obj>,
    section: &'obj SectionInfo,
    pub(crate) offset_in_section: u64,
}

fn read_object_bytes(input_file: &linker_layout::InputFile) -> Result<Vec<u8>> {
    let mut file = std::fs::File::open(&input_file.path)
        .with_context(|| format!("Failed to open `{}`", input_file.path.display()))?;
    let mut buffer = Vec::new();
    if let Some(entry) = input_file.archive_entry.as_ref() {
        buffer.resize(entry.range.end - entry.range.start, 0);
        file.read_exact_at(&mut buffer, entry.range.start as u64)?;
    } else {
        file.read_to_end(&mut buffer)?;
    }
    Ok(buffer)
}

impl InputResolution<'_> {
    pub(crate) fn section_index(&self) -> object::SectionIndex {
        self.section.index()
    }
}

impl SectionInfo {
    pub(crate) fn index(&self) -> object::SectionIndex {
        object::SectionIndex(self.section_index)
    }
}

impl Display for InputFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`", self.filename.display())?;
        if let Some(entry) = self.archive_entry.as_ref() {
            write!(f, " @ `{}`", String::from_utf8_lossy(&entry.identifier))?;
        }
        Ok(())
    }
}
