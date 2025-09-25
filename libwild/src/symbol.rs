use crate::hash::PreHashed;
use object::LittleEndian;
use object::read::elf::Sym as _;
use std::fmt::Display;
use std::ops::BitXor as _;

/// A prehashed symbol that may or may not be versioned. Note, we have the enum as the outer layer
/// and prehash inside the enum. It might be tempting to think that we should do this the other way
/// around. i.e. define a type SymbolName, that's either an enum or has an optional version, then
/// prehash that. However, doing that would mean that the type stored in our names map would be
/// larger which would hurt performance. Benchmarks showed about a 2.4% slowdown just from adding an
/// optional version to the type stored in our names map. So instead, we handle versioned and
/// unversioned symbols separately.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PreHashedSymbolName<'data> {
    Unversioned(PreHashed<UnversionedSymbolName<'data>>),
    Versioned(PreHashed<VersionedSymbolName<'data>>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct UnversionedSymbolName<'data> {
    bytes: &'data [u8],
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VersionedSymbolName<'data> {
    name: UnversionedSymbolName<'data>,
    version: &'data [u8],
}

impl<'data> UnversionedSymbolName<'data> {
    pub(crate) fn new(bytes: &'data [u8]) -> UnversionedSymbolName<'data> {
        Self { bytes }
    }

    pub(crate) fn prehashed(bytes: &'data [u8]) -> PreHashed<UnversionedSymbolName<'data>> {
        PreHashed::new(Self::new(bytes), crate::hash::hash_bytes(bytes))
    }

    pub(crate) fn bytes(&self) -> &'data [u8] {
        self.bytes
    }
}

impl<'data> VersionedSymbolName<'data> {
    pub(crate) fn prehashed(
        name: PreHashed<UnversionedSymbolName<'data>>,
        version: &'data [u8],
    ) -> PreHashed<VersionedSymbolName<'data>> {
        PreHashed::new(
            VersionedSymbolName {
                name: *name,
                version,
            },
            name.hash().bitxor(crate::hash::hash_bytes(version)),
        )
    }
}

impl Display for UnversionedSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(s) = std::str::from_utf8(self.bytes) {
            Display::fmt(s, f)
        } else {
            write!(f, "INVALID UTF-8({:?})", self.bytes)
        }
    }
}

impl std::fmt::Debug for UnversionedSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&String::from_utf8_lossy(self.bytes), f)
    }
}

pub(crate) struct SymDebug<'data>(pub(crate) &'data crate::elf::SymtabEntry);

impl<'data> PreHashedSymbolName<'data> {
    pub(crate) fn from_raw(
        name_info: &crate::symbol_db::RawSymbolName<'data>,
    ) -> PreHashedSymbolName<'data> {
        let name = UnversionedSymbolName::prehashed(name_info.name);
        if let Some(version) = name_info.version_name {
            PreHashedSymbolName::Versioned(VersionedSymbolName::prehashed(name, version))
        } else {
            PreHashedSymbolName::Unversioned(name)
        }
    }
}

impl Display for SymDebug<'_> {
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

        let kind = if sym.is_undefined(e) {
            "Undefined"
        } else {
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
        };

        write!(f, "{vis} {kind}")
    }
}
