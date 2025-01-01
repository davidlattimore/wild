pub(crate) use rayon::*;

pub(crate) fn available_parallelism() -> std::num::NonZeroUsize {
    std::thread::available_parallelism().unwrap_or(std::num::NonZeroUsize::new(1).unwrap())
}
