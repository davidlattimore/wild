use crate::hash::PreHashed;
use object::ObjectSymbol;
use std::fmt::Display;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SymbolName<'data> {
    bytes: &'data [u8],
}

impl<'data> SymbolName<'data> {
    pub(crate) fn new(bytes: &'data [u8]) -> SymbolName<'data> {
        Self { bytes }
    }

    pub(crate) fn prehashed(bytes: &'data [u8]) -> PreHashed<SymbolName<'data>> {
        PreHashed::new(Self::new(bytes), crate::hash::hash_bytes(bytes))
    }

    pub(crate) fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl<'data> Display for SymbolName<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        String::from_utf8_lossy(self.bytes).fmt(f)
    }
}

pub(crate) struct SymDebug<'data, 'file>(pub(crate) crate::elf::Symbol<'data, 'file>);

impl<'data, 'file> Display for SymDebug<'data, 'file> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sym = self.0;
        let vis = if sym.is_local() {
            "Local"
        } else if sym.is_weak() {
            "Weak"
        } else {
            "Global"
        };
        let kind = if sym.is_definition() {
            match sym.kind() {
                object::SymbolKind::Text => "Text",
                object::SymbolKind::Data => "Data",
                object::SymbolKind::Section => "Section",
                object::SymbolKind::File => "File",
                object::SymbolKind::Label => "Label",
                object::SymbolKind::Tls => "Tls",
                _ => "Unknown",
            }
        } else {
            "Undefined"
        };
        write!(f, "{vis} {kind}")
    }
}
