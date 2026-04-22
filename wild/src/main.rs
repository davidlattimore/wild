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

/// The current Wild version as written by build.rs.
const VERSION: &str = include_str!(concat!(env!("OUT_DIR"), "/version.txt"));

fn run() -> libwild::error::Result {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    libwild::init_timing()?;

    // Incremental whole-link skip — runs BEFORE `Args::parse` so
    // we skip the ~274 ms spent walking `-L`, resolving `-l`, and
    // probing the SDK. If the cache side-car alongside the output
    // agrees on (argv hash, wild version, per-input fingerprints,
    // output size), the existing output binary is already the
    // correct link result.
    //
    // Gated on `WILD_INCREMENTAL_DEBUG=1`; no-op when unset.
    if let Some(output) = libwild::try_early_skip_from_argv() {
        libwild::bump_output_path_mtime(&output);
        return Ok(());
    }

    let mut args = libwild::Args::new(std::env::args)?;
    args.set_version(VERSION);
    args.parse(std::env::args)?;

    if libwild::should_fork(&args) {
        // Safety: We haven't spawned any threads yet.
        unsafe { libwild::run_in_subprocess(args) };
    } else {
        // Run the linker in this process without forking.

        // Note, we need to setup tracing before worker, otherwise the threads won't contribute to
        // counters such as --time=cycles,instructions etc.
        libwild::setup_tracing(&args)?;

        libwild::run(args)
    }
}
