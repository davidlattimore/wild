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
    /// Path to the input file on disk. In the of archives, multiple inputs may have the same path.
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

pub fn layout_path(base_path: &Path) -> PathBuf {
    let mut new_extension = base_path.extension().unwrap_or_default().to_owned();
    new_extension.push(".layout");
    base_path.with_extension(new_extension)
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
