use crate::error::Result;
use crate::input_data::FileId;
use anyhow::bail;
use std::fmt::Display;
use std::hash::Hasher;

pub(crate) const PLACEHOLDER: Symbol = Symbol {
    file_id: FileId::placeholder(),
    local_index: object::SymbolIndex(0),
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Symbol {
    pub(crate) file_id: FileId,
    /// An index within the symbols defined by `file_id`. Care needs to be taken when using this
    /// field, since if multiple files define this symbol, then you need to make sure you use the
    /// local index for the right file, which isn't always the first one. That means that it's easy
    /// to use this field incorrectly and have it work most of the time. For this reason this field
    /// should remain private.
    local_index: object::SymbolIndex,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct SymbolName<'data> {
    /// We precompute the hash of bytes since we can do that when running in multiple threads,
    /// saving the time needed to hash the bytes when building the symbol table, which is single
    /// threaded.
    hash: u64,
    bytes: &'data [u8],
}

impl<'data> std::hash::Hash for SymbolName<'data> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // We don't hash bytes because hash is already a hash of the bytes - that's the whole point
        // of storing it.
        self.hash.hash(state);
    }
}

impl<'data> SymbolName<'data> {
    pub(crate) fn placeholder() -> SymbolName<'static> {
        SymbolName::new(&[])
    }

    pub(crate) fn new(bytes: &'data [u8]) -> SymbolName<'data> {
        Self {
            bytes,
            hash: fxhash::hash64(bytes),
        }
    }

    pub(crate) fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl Symbol {
    pub(crate) fn new(file_id: FileId, local_index: object::SymbolIndex) -> Self {
        Self {
            file_id,
            local_index,
        }
    }

    pub(crate) fn local_index_for_file(&self, file_id: FileId) -> Result<object::SymbolIndex> {
        if self.file_id != file_id {
            bail!("Requested local index for a symbol that didn't define that symbol");
        }
        Ok(self.local_index)
    }

    /// Returns the local index without first checking if the file_id is correct. See comment on the
    /// field `local_index`.
    pub(crate) fn local_index_without_checking_file_id(&self) -> object::SymbolIndex {
        self.local_index
    }

    pub(crate) fn set_local_index(&mut self, local_index: object::SymbolIndex) {
        self.local_index = local_index;
    }
}

impl<'data> Display for SymbolName<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        String::from_utf8_lossy(self.bytes).fmt(f)
    }
}
