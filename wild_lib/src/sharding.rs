//! Provides ways to split a Vec or a slice into multiple mutable parts so that each part can be
//! worked on by a separate thread.
//!
//! For now, we do this without unsafe code. This however means that we need to have already
//! initialised the thing we're splitting before we split it. In future, we may want to use unsafe
//! to allow uninitialised memory to be split, worked on, then with some check that all the memory
//! has now been initialised, made available as a single Vec.

use std::ops::Index;
use std::ops::IndexMut;

pub(crate) trait ShardKey: Copy {
    fn zero() -> Self;

    fn add_usize(self, offset: usize) -> Self;

    fn as_usize(self) -> usize;
}

pub(crate) fn split_slice<'sizes, 'data: 'sizes, V>(
    mut input: &'data mut [V],
    sizes: &'sizes [usize],
) -> Vec<&'data mut [V]> {
    sizes
        .iter()
        .map(|&size| crate::slice::slice_take_prefix_mut(&mut input, size))
        .collect()
}

pub(crate) fn split_to_shards<'sizes, 'data: 'sizes, K: ShardKey, V>(
    mut input: &'data mut [V],
    sizes: &'sizes [usize],
) -> Vec<Shard<'data, K, V>> {
    let mut next_offset = K::zero();
    sizes
        .iter()
        .map(|&size| {
            let starting_offset = next_offset;
            next_offset = next_offset.add_usize(size);
            Shard {
                data: crate::slice::slice_take_prefix_mut(&mut input, size),
                start_key: starting_offset,
            }
        })
        .collect()
}

pub(crate) struct Shard<'data, K, V> {
    data: &'data mut [V],
    pub(crate) start_key: K,
}

impl<'data, K: ShardKey, V> Index<K> for Shard<'data, K, V> {
    type Output = V;

    fn index(&self, index: K) -> &Self::Output {
        &self.data[index.as_usize() - self.start_key.as_usize()]
    }
}

impl<'data, K: ShardKey, V> IndexMut<K> for Shard<'data, K, V> {
    fn index_mut(&mut self, index: K) -> &mut Self::Output {
        &mut self.data[index.as_usize() - self.start_key.as_usize()]
    }
}

impl<'data, K: ShardKey, V> Shard<'data, K, V> {
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (K, &mut V)> {
        let s = self.start_key;
        self.data
            .iter_mut()
            .enumerate()
            .map(move |(k, v)| (s.add_usize(k), v))
    }

    pub(crate) fn values_mut(&mut self) -> impl Iterator<Item = &mut V> {
        self.data.iter_mut()
    }
}
