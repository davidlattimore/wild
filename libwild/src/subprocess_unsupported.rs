use crate::Args;
use crate::error::Result;

/// # Safety
/// See function of the same name in `subprocess.rs`
pub unsafe fn run_in_subprocess(args: &crate::Args) -> ! {
    let exit_code = match run_with_args(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            -1
        }
    };
    std::process::exit(exit_code);
}

fn run_with_args(args: &Args) -> Result {
    crate::setup_tracing(args)?;
    crate::setup_thread_pool(args)?;
    let linker = crate::Linker::new();
    linker.run(args)?;
    Ok(())
}
