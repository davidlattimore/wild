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
