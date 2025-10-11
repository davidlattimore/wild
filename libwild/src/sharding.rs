pub(crate) trait ShardKey: Copy {
    fn zero() -> Self;

    fn add_usize(self, offset: usize) -> Self;
}
