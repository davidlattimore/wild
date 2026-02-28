#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::run_in_subprocess;
#[cfg(target_os = "windows")]
pub use windows::run_in_subprocess;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub unsafe fn run_in_subprocess(args: crate::args::ElfArgs) -> ! {
    let exit_code = match crate::run_elf(args) {
        Ok(()) => 0,
        Err(error) => crate::error::report_error_and_exit(&error),
    };
    std::process::exit(exit_code);
}
