//! This crate defines a format for providing information about where a linker put stuff.

use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::io::Write;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Layout {
    /// The input files to the linker.
    pub files: Vec<InputFile>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct InputFile {
    /// Path to the input file on disk. In case of archives, multiple inputs may have the same path.
    pub path: PathBuf,

    /// If the input is an archive, then contains information about where in the archive the file
    /// came from.
    pub archive_entry: Option<ArchiveEntryInfo>,

    /// Sections that were written to the output. Indexes correspond the sections in the input file.
    /// Contains None for sections that were discarded or weren't fully copied.
    pub sections: Vec<Option<Section>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ArchiveEntryInfo {
    /// The range within the file that contains the archive entry (not including the entry header).
    pub range: Range<usize>,

    pub identifier: Vec<u8>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Section {
    pub mem_range: Range<u64>,
}

impl Layout {
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        postcard::to_io(self, writer)?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_stdvec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).context("Invalid linker layout")
    }
}

#[must_use]
pub fn layout_path(base_path: &Path) -> PathBuf {
    // We always want to append, not use with_extension, since we don't want to remove any existing
    // extension, otherwise we'd likely get collisions.
    let mut s = base_path.as_os_str().to_owned();
    s.push(".layout");
    PathBuf::from(s)
}

impl std::fmt::Display for InputFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.path.display().fmt(f)?;
        if let Some(e) = self.archive_entry.as_ref() {
            write!(f, " @ {}", String::from_utf8_lossy(&e.identifier))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let layout = Layout {
            files: vec![InputFile {
                path: PathBuf::new(),
                archive_entry: None,
                sections: vec![Some(Section { mem_range: 42..48 })],
            }],
        };
        let bytes = layout.to_bytes().unwrap();
        let layout2 = Layout::from_bytes(&bytes).unwrap();
        assert_eq!(layout, layout2);
    }
}
