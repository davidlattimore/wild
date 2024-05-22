use crate::Result;
use anyhow::bail;
use anyhow::Context;
use linker_layout::ArchiveEntryInfo;
use std::fmt::Display;
use std::io::Read;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;

pub(crate) struct IndexedLayout {
    files: Vec<InputFile>,
    sections: Vec<SectionInfo>,
}

impl IndexedLayout {
    fn new(layout: linker_layout::Layout) -> Result<IndexedLayout> {
        let mut files = Vec::with_capacity(layout.files.len());
        let mut sections = Vec::new();
        for (file_index, file) in layout.files.into_iter().enumerate() {
            files.push(InputFile {
                filename: file.path,
                archive_entry: file.archive_entry,
            });
            sections.extend(file.sections.into_iter().enumerate().filter_map(
                |(section_index, maybe_sec)| {
                    maybe_sec.map(|sec| SectionInfo {
                        addresses: sec.mem_range,
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

struct DisplaySection {
    info: SectionInfo,
    file: InputFile,
}

impl DisplaySection {
    fn new(info: &SectionInfo, files: &[InputFile]) -> Self {
        Self {
            info: info.clone(),
            file: files[info.section_index].clone(),
        }
    }
}

impl Display for DisplaySection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use object::Object as _;
        use object::ObjectSection as _;

        let object_bytes = match self.file.read_object_bytes() {
            Ok(b) => b,
            Err(error) => {
                write!(f, "<{error}>")?;
                return Ok(());
            }
        };
        let elf_file = match crate::ElfFile64::parse(&object_bytes) {
            Ok(f) => f,
            Err(error) => {
                write!(f, "<{error}>")?;
                return Ok(());
            }
        };
        if let Ok(section_name) = elf_file
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

#[derive(Clone)]
pub(crate) struct InputFile {
    filename: PathBuf,
    archive_entry: Option<ArchiveEntryInfo>,
}

pub(crate) struct InputResolution<'obj> {
    pub(crate) file: &'obj InputFile,
    section: &'obj SectionInfo,
    pub(crate) offset_in_section: u64,
}

impl InputFile {
    pub(crate) fn read_object_bytes(&self) -> Result<Vec<u8>> {
        let mut file = std::fs::File::open(&self.filename)
            .with_context(|| format!("Failed to open `{}`", self.filename.display()))?;
        let mut buffer = Vec::new();
        if let Some(entry) = self.archive_entry.as_ref() {
            buffer.resize(entry.range.end - entry.range.start, 0);
            file.read_exact_at(&mut buffer, entry.range.start as u64)?;
        } else {
            file.read_to_end(&mut buffer)?;
        }
        Ok(buffer)
    }
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

pub(crate) fn for_path(path: &std::path::Path) -> Result<Option<IndexedLayout>> {
    let layout_path = linker_layout::layout_path(path);
    layout_path
        .exists()
        .then(|| std::fs::read(layout_path))
        .transpose()?
        .map(|layout_bytes| linker_layout::Layout::from_bytes(&layout_bytes))
        .transpose()?
        .map(IndexedLayout::new)
        .transpose()
}

impl Display for InputFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`", self.filename.display())?;
        if let Some(entry) = self.archive_entry.as_ref() {
            write!(f, " @ `{}`", String::from_utf8_lossy(&entry.identifier))?;
        }
        Ok(())
    }
}
