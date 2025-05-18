//! This crate defines a format for storing debug traces associated with particular addresses in the
//! linker output.

use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use std::io::Write;
use std::ops::Range;
use std::path::Path;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Default)]
pub struct TraceData {
    pub traces: Vec<AddressTrace>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct AddressTrace {
    pub address: u64,
    pub messages: Vec<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct Section {
    pub mem_range: Range<u64>,
}

impl TraceData {
    pub fn write(&self, writer: &mut impl Write) -> Result<()> {
        //postcard::to_io(self, writer)?;
        let r = postcard::to_io(self, writer);
        let r: Result<()> = r.map(|_| ()).map_err(|e| e.into());
        r?;
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(postcard::to_stdvec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).context("Invalid linker trace")
    }
}

#[must_use]
pub fn trace_path(base_path: &Path) -> PathBuf {
    let mut new_extension = base_path.extension().unwrap_or_default().to_owned();
    new_extension.push(".trace");
    base_path.with_extension(new_extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        let layout = TraceData {
            traces: vec![AddressTrace {
                address: 100,
                messages: vec!["Test".to_owned()],
            }],
        };
        let bytes = layout.to_bytes().unwrap();
        let layout2 = TraceData::from_bytes(&bytes).unwrap();
        assert_eq!(layout, layout2);
    }
}
