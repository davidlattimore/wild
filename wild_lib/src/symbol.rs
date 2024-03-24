use crate::hash::PreHashed;
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
