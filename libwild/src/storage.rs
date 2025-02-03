//! The storage module abstracts over state that might just be in memory or might be on disk. In
//! memory is faster while on-disk is needed when doing incremental linking.

use crate::hash::PassThroughHashMap;
use crate::hash::PreHashed;
use crate::symbol::PreHashedSymbolName;
use crate::symbol::UnversionedSymbolName;
use crate::symbol::VersionedSymbolName;
use crate::symbol_db::SymbolId;
use std::panic::RefUnwindSafe;

pub(crate) trait StorageModel: Send + Sync + RefUnwindSafe {
    type SymbolNameMap<'data>: SymbolNameMap<'data>;
}

pub(crate) trait SymbolNameMap<'data>: Send + Sync + RefUnwindSafe {
    fn empty() -> Self;

    fn reserve(&mut self, capacity: usize);

    fn get_unversioned(&self, key: &PreHashed<UnversionedSymbolName>) -> Option<SymbolId>;

    fn get(&self, key: &PreHashedSymbolName) -> Option<SymbolId>;

    fn entry(
        &mut self,
        key: PreHashed<UnversionedSymbolName<'data>>,
    ) -> std::collections::hash_map::Entry<'_, PreHashed<UnversionedSymbolName<'data>>, SymbolId>;

    fn versioned_entry(
        &mut self,
        key: PreHashed<VersionedSymbolName<'data>>,
    ) -> std::collections::hash_map::Entry<'_, PreHashed<VersionedSymbolName<'data>>, SymbolId>;

    fn all_symbols(&self) -> impl Iterator<Item = (&PreHashed<UnversionedSymbolName>, &SymbolId)>;
}

pub(crate) struct InMemory;

impl StorageModel for InMemory {
    type SymbolNameMap<'data> = InMemorySymbolNameMap<'data>;
}

pub(crate) struct InMemorySymbolNameMap<'data> {
    name_to_id: PassThroughHashMap<UnversionedSymbolName<'data>, SymbolId>,
    versioned_name_to_id: PassThroughHashMap<VersionedSymbolName<'data>, SymbolId>,
}

impl<'data> SymbolNameMap<'data> for InMemorySymbolNameMap<'data> {
    fn empty() -> Self {
        Self {
            name_to_id: Default::default(),
            versioned_name_to_id: Default::default(),
        }
    }

    fn reserve(&mut self, additional: usize) {
        self.name_to_id.reserve(additional);
    }

    fn get_unversioned(&self, key: &PreHashed<UnversionedSymbolName>) -> Option<SymbolId> {
        self.name_to_id.get(key).copied()
    }

    fn get(&self, key: &PreHashedSymbolName) -> Option<SymbolId> {
        match key {
            PreHashedSymbolName::Unversioned(key) => self.name_to_id.get(key).copied(),
            PreHashedSymbolName::Versioned(key) => self.versioned_name_to_id.get(key).copied(),
        }
    }

    fn entry(
        &mut self,
        key: PreHashed<UnversionedSymbolName<'data>>,
    ) -> std::collections::hash_map::Entry<'_, PreHashed<UnversionedSymbolName<'data>>, SymbolId>
    {
        self.name_to_id.entry(key)
    }

    fn versioned_entry(
        &mut self,
        key: PreHashed<VersionedSymbolName<'data>>,
    ) -> std::collections::hash_map::Entry<'_, PreHashed<VersionedSymbolName<'data>>, SymbolId>
    {
        self.versioned_name_to_id.entry(key)
    }

    fn all_symbols(&self) -> impl Iterator<Item = (&PreHashed<UnversionedSymbolName>, &SymbolId)> {
        self.name_to_id.iter()
    }
}
