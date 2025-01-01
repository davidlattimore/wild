pub(crate) trait ShardKey: Copy {
    fn zero() -> Self;

    fn add_usize(self, offset: usize) -> Self;

    fn as_usize(self) -> usize;
}
