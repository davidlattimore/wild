//! COFF object file wrapper for PE linking.
//!
//! Provides a unified interface over regular COFF and COFF bigobj files
//! using the `object` crate's parsing support.

use crate::error::Context as _;
use crate::error::Result;
use object::pe;
use object::read::coff::CoffHeader;
use object::read::coff::ImageSymbol;
use object::read::coff::SectionTable;

/// A parsed COFF object file, abstracting over regular and bigobj formats.
pub(crate) enum CoffFile<'data> {
    Regular {
        file: object::read::coff::CoffFile<'data>,
        data: &'data [u8],
    },
    Big {
        file: object::read::coff::CoffBigFile<'data>,
        data: &'data [u8],
    },
}

impl<'data> CoffFile<'data> {
    pub(crate) fn parse(data: &'data [u8]) -> Result<Self> {
        let kind = object::FileKind::parse(data).context("Failed to identify COFF file kind")?;
        match kind {
            object::FileKind::Coff => {
                let file = object::read::coff::CoffFile::parse(data)
                    .context("Failed to parse COFF object")?;
                Ok(CoffFile::Regular { file, data })
            }
            object::FileKind::CoffBig => {
                let file = object::read::coff::CoffBigFile::parse(data)
                    .context("Failed to parse COFF bigobj")?;
                Ok(CoffFile::Big { file, data })
            }
            _ => crate::bail!("Not a COFF file"),
        }
    }

    pub(crate) fn machine(&self) -> u16 {
        match self {
            CoffFile::Regular { file, .. } => file.coff_header().machine(),
            CoffFile::Big { file, .. } => file.coff_header().machine(),
        }
    }

    pub(crate) fn sections(&self) -> SectionTable<'data> {
        match self {
            CoffFile::Regular { file, .. } => file.coff_section_table(),
            CoffFile::Big { file, .. } => file.coff_section_table(),
        }
    }

    /// Iterate over symbols, calling the callback with
    /// (symbol name, section number, storage class, value).
    pub(crate) fn for_each_symbol(
        &self,
        mut cb: impl FnMut(&[u8], i32, u8, u32) -> Result<()>,
    ) -> Result<()> {
        match self {
            CoffFile::Regular { file, .. } => {
                let symbols = file.coff_symbol_table();
                for (_index, symbol) in symbols.iter() {
                    let name = symbol
                        .name(symbols.strings())
                        .context("Failed to read symbol name")?;
                    cb(
                        name,
                        symbol.section_number() as i32,
                        symbol.storage_class(),
                        symbol.value(),
                    )?;
                }
            }
            CoffFile::Big { file, .. } => {
                let symbols = file.coff_symbol_table();
                for (_index, symbol) in symbols.iter() {
                    let name = symbol
                        .name(symbols.strings())
                        .context("Failed to read symbol name")?;
                    cb(
                        name,
                        symbol.section_number() as i32,
                        symbol.storage_class(),
                        symbol.value(),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Get the raw data for a section by its 1-based index.
    pub(crate) fn section_data(
        &self,
        index: object::read::SectionIndex,
    ) -> Result<&'data [u8]> {
        let section = self
            .sections()
            .section(index)
            .with_context(|| format!("Invalid section index {}", index.0))?;
        match self {
            CoffFile::Regular { data, .. } => section
                .coff_data(*data)
                .map_err(|()| crate::error!("Failed to read section {} data", index.0)),
            CoffFile::Big { data, .. } => section
                .coff_data(*data)
                .map_err(|()| crate::error!("Failed to read section {} data", index.0)),
        }
    }

    /// Get relocations for a section by its 1-based index.
    pub(crate) fn section_relocations(
        &self,
        index: object::read::SectionIndex,
    ) -> Result<&'data [pe::ImageRelocation]> {
        let section = self
            .sections()
            .section(index)
            .with_context(|| format!("Invalid section index {}", index.0))?;
        match self {
            CoffFile::Regular { data, .. } => section
                .coff_relocations(*data)
                .with_context(|| format!("Failed to read section {} relocations", index.0)),
            CoffFile::Big { data, .. } => section
                .coff_relocations(*data)
                .with_context(|| format!("Failed to read section {} relocations", index.0)),
        }
    }
}
