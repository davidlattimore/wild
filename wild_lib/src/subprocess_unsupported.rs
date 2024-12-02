use crate::Linker;

/// # Safety
/// See function of the same name in `subprocess.rs`
pub unsafe fn run_in_subprocess(linker: &Linker) -> ! {
    let exit_code = match linker.run() {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            -1
        }
    };
    std::process::exit(exit_code);
}
