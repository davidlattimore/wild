//! Code to read ar files. We don't use the ar crate because it provides access to data only via the
//! Read trait and we want to borrow the data of each entry. We do however use the ar crate as a dev
//! dependency in our tests so that we can verify consistency.

use crate::error::Result;
use std::ffi::OsStr;
use std::ops::Range;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

pub(crate) enum ArchiveEntry<'data> {
    Regular(ArchiveContent<'data>),
    Thin(ThinEntry<'data>),
}

#[derive(Clone, Copy)]
pub(crate) struct Identifier<'data> {
    data: &'data [u8],
}

#[derive(Clone, Copy)]
pub(crate) struct EntryMeta<'data> {
    pub(crate) identifier: Identifier<'data>,

    /// Where in the original archive file the entry came from, not including the entry header.
    pub(crate) start_offset: usize,

    // Exclusive end offset of where the entry came from in the archive.
    pub(crate) end_offset: usize,
}

pub(crate) struct ArchiveContent<'data> {
    pub(crate) ident: Identifier<'data>,

    pub(crate) entry_data: &'data [u8],

    /// The offset in the archive at which the data is from.
    pub(crate) data_offset: usize,
}

pub(crate) struct ThinEntry<'data> {
    pub(crate) ident: Identifier<'data>,
}

pub(crate) struct ArchiveIterator<'data> {
    data: &'data [u8],
    is_thin: bool,
    iter: object::read::archive::ArchiveMemberIterator<'data>,
}

impl<'data> ArchiveIterator<'data> {
    /// Create an iterator from the bytes of the whole archive. The supplied bytes should start with
    /// an archive entry.
    pub(crate) fn from_archive_bytes(data: &'data [u8]) -> Result<Self> {
        let file = object::read::archive::ArchiveFile::parse(data)?;

        Ok(Self {
            data,
            is_thin: file.is_thin(),
            iter: file.members(),
        })
    }
}

impl<'data> Iterator for ArchiveIterator<'data> {
    type Item = Result<ArchiveEntry<'data>>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.iter.next() {
            Some(Ok(member)) => Some(Ok(if self.is_thin {
                ArchiveEntry::Thin(ThinEntry {
                    ident: Identifier {
                        data: member.name(),
                    },
                })
            } else {
                ArchiveEntry::Regular(ArchiveContent {
                    ident: Identifier {
                        data: member.name(),
                    },
                    entry_data: member.data(self.data).unwrap(),
                    data_offset: member.file_range().0 as usize,
                })
            })),
            Some(Err(e)) => Some(Err(e.into())),
            None => None,
        }
    }
}

impl<'data> Identifier<'data> {
    pub(crate) fn as_slice(&self) -> &'data [u8] {
        self.data
    }

    pub(crate) fn as_path(&self) -> &'data std::path::Path {
        Path::new(OsStr::from_bytes(self.as_slice()))
    }
}

impl<'data> EntryMeta<'data> {
    pub(crate) fn byte_range(&self) -> Range<usize> {
        self.start_offset..self.end_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bail;
    use crate::error::Context as _;
    use crate::error::Result;
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
                for entry in ArchiveIterator::from_archive_bytes(&data)? {
                    let entry = entry?;
                    match entry {
                        ArchiveEntry::Regular(content) => {
                            our_entries.push(content);
                        }
                        ArchiveEntry::Thin(_) => {
                            bail!("This test does not support thin archives");
                        }
                    }
                }
                if ar_summary.entries.len() != our_entries.len() {
                    for x in &our_entries {
                        println!("{}", x.ident.as_path().display());
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
                    let b = b.ident.as_slice();
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
}
