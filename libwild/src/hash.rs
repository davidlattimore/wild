use std::collections::HashMap;
use std::hash::BuildHasher;
use std::hash::Hasher;
use std::ops::Deref;

pub(crate) type PassThroughHashMap<K, V> = HashMap<PreHashed<K>, V, PassThroughHasher>;

#[derive(Default)]
pub(crate) struct PassThroughHasher {
    hash: u64,
}

impl Hasher for PassThroughHasher {
    fn finish(&self) -> u64 {
        self.hash
    }

    fn write_u64(&mut self, i: u64) {
        self.hash = i;
    }

    fn write(&mut self, _bytes: &[u8]) {
        panic!("PassThroughHasher used with inappropriate hash implementation");
    }
}

impl BuildHasher for PassThroughHasher {
    type Hasher = PassThroughHasher;

    fn build_hasher(&self) -> Self::Hasher {
        PassThroughHasher::default()
    }
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = foldhash::fast::FixedState::default().build_hasher();
    hasher.write(bytes);
    hasher.finish()
}

#[derive(Eq, Clone, Copy)]
pub(crate) struct PreHashed<T> {
    value: T,
    hash: u64,
}

impl<T: PartialEq> PartialEq for PreHashed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> PreHashed<T> {
    pub(crate) fn new(value: T, hash: u64) -> Self {
        Self { value, hash }
    }

    pub(crate) fn hash(&self) -> u64 {
        self.hash
    }
}

impl<T> std::hash::Hash for PreHashed<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
    }
}

impl<T> Deref for PreHashed<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}
