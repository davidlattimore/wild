/// # Safety
/// See function of the same name in `subprocess.rs`
pub unsafe fn run_in_subprocess(args: crate::args::ElfArgs) -> ! {
    let exit_code = match crate::run_elf(args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{}", error.to_string());
            -1
        }
    };
    std::process::exit(exit_code);
}
