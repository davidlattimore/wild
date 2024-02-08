use std::collections::HashMap;
use std::hash::Hasher;
use std::hash::BuildHasher;

pub(crate) type PassThroughHashMap<K, V> = HashMap<K, V, PassThroughHasher>;

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
