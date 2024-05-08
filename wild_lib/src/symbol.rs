use crate::hash::PreHashed;
use object::read::elf::Sym as _;
use object::LittleEndian;
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

pub(crate) struct SymDebug<'data>(pub(crate) &'data crate::elf::SymtabEntry);

impl<'data> Display for SymDebug<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let e = LittleEndian;
        let sym = self.0;
        let vis = if sym.is_local() {
            "Local"
        } else if sym.is_weak() {
            "Weak"
        } else {
            "Global"
        };
        let kind = if sym.is_definition(e) {
            match sym.st_type() {
                object::elf::STT_FUNC => "Func",
                object::elf::STT_GNU_IFUNC => "IFunc",
                object::elf::STT_OBJECT => "Data",
                object::elf::STT_COMMON => "Common",
                object::elf::STT_SECTION => "Section",
                object::elf::STT_FILE => "File",
                object::elf::STT_NOTYPE => "NoType",
                object::elf::STT_TLS => "Tls",
                _ => "Unknown",
            }
        } else {
            "Undefined"
        };
        write!(f, "{vis} {kind}")
    }
}
