//! Code to read ar files. We don't use the ar crate because it provides access to data only via the
//! Read trait and we want to borrow the data of each entry. We do however use the ar crate as a dev
//! dependency in our tests so that we can verify consistency.

use crate::error::Result;
use anyhow::bail;
use anyhow::Context;
use bytemuck::Pod;
use bytemuck::Zeroable;
use std::ops::Range;

pub(crate) enum ArchiveEntry<'data> {
    Regular(ArchiveContent<'data>),
    // TODO: Consider if we want to keep this.
    #[allow(dead_code)]
    Symbols(SymbolTable<'data>),
    Filenames(ExtendedFilenames<'data>),
}

#[derive(Clone, Copy)]
pub(crate) struct ExtendedFilenames<'data> {
    data: &'data [u8],
}

#[derive(Clone, Copy)]
pub(crate) struct Identifier<'data> {
    /// The start of the identifier. We don't yet know where the identifier ends and compute that
    /// on-demand to avoid needing to read the memory unless we actually have to.
    data: &'data [u8],
}

#[derive(Clone)]
pub(crate) struct EntryMeta<'data> {
    pub(crate) identifier: Identifier<'data>,

    /// Where in the original archive file the entry came from, not including the entry header.
    pub(crate) from: Range<usize>,
}

pub(crate) struct ArchiveContent<'data> {
    ident: &'data str,
    pub(crate) entry_data: &'data [u8],

    /// The offset in the archive at which the data is from.
    pub(crate) data_offset: usize,
}

// TODO: Consider if we want to keep this.
#[allow(dead_code)]
pub(crate) struct SymbolTable<'data> {
    pub(crate) data: &'data [u8],
}

pub(crate) struct ArchiveIterator<'data> {
    data: &'data [u8],
    offset: usize,
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
struct EntryHeader {
    ident: [u8; 16],
    _timestamp: [u8; 12],
    _owner_id: [u8; 6],
    _group_id: [u8; 6],
    _mode: [u8; 8],
    size: [u8; 10],
    end: [u8; 2],
}

const _ASSERTS: () = {
    assert!(size_of::<EntryHeader>() == 60);
};

const HEADER_SIZE: usize = size_of::<EntryHeader>();

impl<'data> ArchiveIterator<'data> {
    /// Create an iterator from the bytes of the whole archive. The supplied bytes should start with
    /// an archive entry.
    pub(crate) fn from_archive_bytes(data: &'data [u8]) -> Result<Self> {
        let magic = b"!<arch>\n";
        let Some(data) = data.strip_prefix(magic) else {
            bail!("Missing header");
        };
        Ok(Self {
            data,
            offset: magic.len(),
        })
    }

    fn next_result(&mut self) -> Result<Option<ArchiveEntry<'data>>> {
        if self.data.is_empty() {
            return Ok(None);
        }
        if self.data.len() < HEADER_SIZE {
            bail!("Short entry header");
        }
        let (header, rest) = self.data.split_at(HEADER_SIZE);
        let header: &EntryHeader = bytemuck::from_bytes(header);
        let bytes: &[u8] = &header.size;
        let size: usize = parse_decimal_int(bytes);
        self.data = rest;
        self.offset += HEADER_SIZE;
        if self.data.len() < size {
            bail!(
                "Entry size is {size}, but only {} bytes left",
                self.data.len()
            );
        }
        let ident = std::str::from_utf8(&header.ident).context("archive ident is invalid UTF-8")?;
        let ident = ident.trim();
        let entry_data = &self.data[..size];
        let entry = match ident {
            "/" => ArchiveEntry::Symbols(SymbolTable { data: entry_data }),
            "//" => ArchiveEntry::Filenames(ExtendedFilenames { data: entry_data }),
            _ => ArchiveEntry::Regular(ArchiveContent {
                ident,
                entry_data,
                data_offset: self.offset,
            }),
        };
        let size_with_padding = size.next_multiple_of(2).min(self.data.len());
        self.data = &self.data[size_with_padding..];
        self.offset += size_with_padding;
        Ok(Some(entry))
    }
}

fn parse_decimal_int(bytes: &[u8]) -> usize {
    // Note, this function shows up in profiles as using a significant amount of time. It's likely
    // that the time is actually just because it's the first time we're reading this bit of memory
    // and the time is actually being spent by the kernel setting up page mappings.
    let mut value = 0;
    for &byte in bytes {
        if !byte.is_ascii_digit() {
            break;
        }
        value = value * 10 + ((byte - b'0') as usize);
    }
    value
}

impl<'data> ArchiveContent<'data> {
    /// Returns the identifier (generally a filename) that identifies this entry. The entry's
    /// identifier may be stored in the entry's header, or it may be in the extended filenames
    /// entry, in which case it will be obtained from `extended_filenames` if present. Since we
    /// generally only need entry identifiers if there's an error, we avoid reading the actual bytes
    /// of the filename, deferring that work until we find that we actually need to, when
    /// `Identifier::as_slice` is called.
    pub(crate) fn identifier(
        &self,
        extended_filenames: Option<ExtendedFilenames<'data>>,
    ) -> Identifier<'data> {
        if let Some(filenames) = extended_filenames {
            if let Some(rest) = self.ident.strip_prefix('/') {
                if let Ok(offset) = rest.parse() {
                    return Identifier {
                        data: &filenames.data[offset..],
                    };
                }
            }
        }
        Identifier {
            data: self.ident.as_bytes(),
        }
    }

    pub(crate) fn data_range(&self) -> Range<usize> {
        self.data_offset..self.data_offset + self.entry_data.len()
    }
}

impl<'data> Identifier<'data> {
    pub(crate) fn as_slice(&self) -> &'data [u8] {
        let end = memchr::memchr(b'/', self.data).unwrap_or(self.data.len());
        &self.data[..end]
    }
}

impl<'data> Iterator for ArchiveIterator<'data> {
    type Item = Result<ArchiveEntry<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_result().transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use anyhow::bail;
    use anyhow::Context;
    use std::io::Read;
    use std::path::Path;

    #[derive(Default)]
    struct Summary {
        entries: Vec<Vec<u8>>,
        identifiers: Vec<Vec<u8>>,
        symbols: Vec<Vec<u8>>,
    }

    fn ar_read_entries(path: &Path) -> Result<Summary> {
        let mut summary = Summary::default();
        let mut archive = ar::Archive::new(std::fs::File::open(path)?);
        while let Some(entry) = archive.next_entry() {
            let mut entry = entry?;
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            summary.entries.push(bytes);
            summary
                .identifiers
                .push(entry.header().identifier().to_owned());
        }
        {
            let mut archive = ar::Archive::new(std::fs::File::open(path)?);
            for symbol in archive.symbols()? {
                summary.symbols.push(symbol.to_owned());
            }
        }
        Ok(summary)
    }

    fn check_consistency(path: &Path, limit: &mut u32) -> Result {
        fn inner(path: &Path, limit: &mut u32) -> Result {
            if *limit == 0 {
                return Ok(());
            }
            if path.is_symlink() {
                // Ignore symlinks so that we don't get into any infinite loops.
            } else if path.is_dir() {
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    check_consistency(&entry.path(), limit)?;
                    if *limit == 0 {
                        return Ok(());
                    }
                }
            } else if path.extension().is_some_and(|ext| ext == "a") {
                *limit -= 1;
                let ar_summary = ar_read_entries(path)?;
                let data = std::fs::read(path)?;
                let mut our_entries = Vec::new();
                let mut filenames = None;
                for entry in ArchiveIterator::from_archive_bytes(&data)? {
                    let entry = entry?;
                    match entry {
                        ArchiveEntry::Regular(content) => {
                            our_entries.push(content);
                        }
                        ArchiveEntry::Symbols(_symbol_table) => {}
                        ArchiveEntry::Filenames(table) => filenames = Some(table),
                    }
                }
                if ar_summary.entries.len() != our_entries.len() {
                    for x in &our_entries {
                        println!("{}", x.ident);
                    }
                    bail!(
                        "ar read {} entries, but we read {}",
                        ar_summary.entries.len(),
                        our_entries.len()
                    );
                }
                for (a, b) in ar_summary.entries.iter().zip(our_entries.iter()) {
                    if a.len() != b.entry_data.len() {
                        bail!(
                            "Different data lengths {} vs {}",
                            a.len(),
                            b.entry_data.len()
                        );
                    }
                    if a != b.entry_data {
                        bail!("Different data");
                    }
                }
                for (a, b) in ar_summary.identifiers.iter().zip(our_entries.iter()) {
                    let b = b.identifier(filenames).as_slice();
                    if a != b {
                        let a = String::from_utf8_lossy(a);
                        let b = String::from_utf8_lossy(b);
                        bail!("Entry filenames differ '{a}' vs '{b}'");
                    }
                }
            }
            Ok(())
        }

        inner(path, limit).with_context(|| format!("Failed to process {}", path.display()))
    }

    #[test]
    fn test_ar_consistency() {
        let mut limit = 1;
        check_consistency(Path::new("src/test_data/a.a"), &mut limit).unwrap();
        // Make sure that we found the file
        assert_eq!(limit, 0);
    }

    #[test]
    fn test_parse_decimal_int() {
        assert_eq!(parse_decimal_int(b"123   "), 123);
        assert_eq!(parse_decimal_int(b"0   "), 0);
    }
}
