//! This module is a drop-in replacement for the parts of rayon that we use. This is mostly intended
//! when profiling, since having rayon makes the profiles harder to read.

use std::marker::PhantomData;
use std::num::NonZeroUsize;

pub(crate) mod prelude {
    pub(crate) use super::IntoParallelIterator;
    pub(crate) use super::IntoParallelRefIterator;
    pub(crate) use super::IntoParallelRefMutIterator;
    pub(crate) use super::ParallelSliceMut;
}

pub(crate) trait IntoParallelIterator {
    type Item: Send;
    type Iter: Iterator<Item = Self::Item>;

    fn into_par_iter(self) -> Self::Iter;
}

impl<T> IntoParallelIterator for T
where
    T: IntoIterator,
    T::Item: Send,
{
    type Item = T::Item;
    type Iter = T::IntoIter;

    fn into_par_iter(self) -> Self::Iter {
        self.into_iter()
    }
}

pub(crate) trait IntoParallelRefIterator<'data> {
    type Iter: Iterator<Item = Self::Item>;
    type Item: Send + 'data;

    fn par_iter(&'data self) -> Self::Iter;
}

impl<'data, I: 'data + ?Sized> IntoParallelRefIterator<'data> for I
where
    &'data I: IntoParallelIterator,
{
    type Iter = <&'data I as IntoParallelIterator>::Iter;
    type Item = <&'data I as IntoParallelIterator>::Item;

    fn par_iter(&'data self) -> Self::Iter {
        self.into_par_iter()
    }
}

pub(crate) trait IntoParallelRefMutIterator<'data> {
    type Iter: IntoParallelIterator<Item = Self::Item>;
    type Item: Send + 'data;

    fn par_iter_mut(&'data mut self) -> Self::Iter;
}

impl<'data, I: 'data + ?Sized> IntoParallelRefMutIterator<'data> for I
where
    &'data mut I: IntoParallelIterator,
{
    type Iter = <&'data mut I as IntoParallelIterator>::Iter;
    type Item = <&'data mut I as IntoParallelIterator>::Item;

    fn par_iter_mut(&'data mut self) -> Self::Iter {
        self.into_par_iter()
    }
}

pub(crate) fn spawn<F>(func: F)
where
    F: FnOnce() + Send + 'static,
{
    func();
}

pub(crate) struct Scope<'scope> {
    _scope: PhantomData<&'scope ()>,
}

impl<'scope> Scope<'scope> {
    pub(crate) fn spawn<F>(&self, func: F)
    where
        F: FnOnce(&Scope<'scope>) + Send + 'scope,
    {
        func(self);
    }
}

pub(crate) fn scope<'scope, F>(func: F)
where
    F: FnOnce(&Scope<'scope>) + Send + 'scope,
{
    let scope = Scope {
        _scope: Default::default(),
    };
    func(&scope);
}

pub(crate) struct ThreadPoolBuilder {}

#[derive(Debug)]
pub(crate) struct ThreadPoolBuildError;

impl std::fmt::Display for ThreadPoolBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ThreadPoolBuildError")
    }
}

impl std::error::Error for ThreadPoolBuildError {}

impl ThreadPoolBuilder {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn num_threads(self, _: usize) -> Self {
        self
    }

    pub(crate) fn build_global(self) -> Result<ThreadPool, ThreadPoolBuildError> {
        Ok(ThreadPool {})
    }
}

pub(crate) struct ThreadPool {}

pub(crate) trait ParallelSliceMut<T: Send> {
    fn as_slice_mut(&mut self) -> &mut [T];

    fn par_sort_unstable_by_key<K, F>(&mut self, f: F)
    where
        K: Ord,
        F: Fn(&T) -> K + Sync,
    {
        self.as_slice_mut().sort_unstable_by_key(f);
    }
}

impl<T: Send> ParallelSliceMut<T> for [T] {
    fn as_slice_mut(&mut self) -> &mut [T] {
        self
    }
}

pub(crate) fn available_parallelism() -> NonZeroUsize {
    NonZeroUsize::new(1).unwrap()
}
