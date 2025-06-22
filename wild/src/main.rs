#[cfg(feature = "mimalloc")]
#[global_allocator]
static MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    if let Err(error) = run() {
        libwild::error::report_error_and_exit(&error)
    }
}

fn run() -> libwild::error::Result {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    let mut args = libwild::Args::parse(|| std::env::args().skip(1))?;

    if args.should_fork() {
        // Safety: We haven't spawned any threads yet.
        unsafe { libwild::run_in_subprocess(&mut args) };
    } else {
        // Run the linker in this process without forking.
        libwild::run(&mut args)
    }
}
