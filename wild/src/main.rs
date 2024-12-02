#[cfg(feature = "mimalloc")]
#[global_allocator]
static MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> wild_lib::error::Result {
    let linker = wild_lib::Linker::from_args(std::env::args().skip(1))?;

    if linker.should_fork() {
        // Safety: We haven't spawned any threads yet.
        unsafe { wild_lib::run_in_subprocess(&linker) };
    } else {
        // Run the linker in this process without forking.
        linker.run()
    }
}
