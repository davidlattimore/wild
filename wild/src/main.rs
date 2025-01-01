#[cfg(feature = "mimalloc")]
#[global_allocator]
static MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> libwild::error::Result {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    let linker = libwild::Linker::from_args(std::env::args().skip(1))?;

    if linker.should_fork() {
        // Safety: We haven't spawned any threads yet.
        unsafe { libwild::run_in_subprocess(&linker) };
    } else {
        // Run the linker in this process without forking.
        linker.run()
    }
}
