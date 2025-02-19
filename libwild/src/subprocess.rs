use crate::Linker;
use crate::error::Result;
use anyhow::Context as _;
use anyhow::anyhow;
use libc::c_char;
use libc::fork;
use libc::pid_t;
use std::ffi::c_int;
use std::ffi::c_void;
use std::io::Error;

/// Runs the linker, in a subprocess if possible, prints any errors, then exits.
///
/// This is done by forking a sub-process which runs the linker and waits for communication back
/// from the sub-process (via a pipe) when the main link task is done (the output file has been
/// written, but some shutdown tasks remain.
///
/// # Safety
/// Must not be called once threads have been spawned. Calling this function from main is generally
/// the best way to ensure this.
pub unsafe fn run_in_subprocess(linker: &Linker) -> ! {
    let exit_code = match subprocess_result(linker) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Error: {error:?}");
            -1
        }
    };
    std::process::exit(exit_code);
}

fn subprocess_result(linker: &Linker) -> Result<i32> {
    let mut fds: [c_int; 2] = [0; 2];
    // create the pipe used to communicate between the parent and child processes - exit on failure
    make_pipe(&mut fds).context("make_pipe")?;

    // Safety: The function we're in is private to this module and is only called from
    // run_in_subprocess, which imposed the requirement that threads have not yet been started on
    // its caller.
    match unsafe { fork() } {
        0 => {
            // Fork success in child - Run linker in this process.
            let done_closure = move || inform_parent_done(&fds);
            linker.run_with_callback(Some(Box::new(done_closure)))?;
            Ok(0)
        }
        -1 => {
            // Fork failure in the parent - Fallback to running linker in this process
            linker.run()?;
            Ok(0)
        }
        pid => {
            // Fork success in the parent - wait for the child to "signal" us it's done
            let exit_status = wait_for_child_done(&fds, pid);
            Ok(exit_status)
        }
    }
}

/// Inform the parent process that work of linker is done and that it succeeded.
fn inform_parent_done(fds: &[c_int]) {
    unsafe {
        libc::close(fds[0]);
        let stream = libc::fdopen(fds[1], "w".as_ptr() as *const c_char);
        let bytes: [u8; 1] = [b'X'];
        libc::fwrite(bytes.as_ptr() as *const c_void, 1, 1, stream);
        libc::fclose(stream);
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
}

/// Wait for the child process to signal it is done, by sending a byte on the pipe. In the case the
/// child crashes, or exits via some path that doesn't send a byte, then the pipe will be closed and
/// we'll then wait for the subprocess to exit, returning its exit code.
fn wait_for_child_done(fds: &[c_int], child_pid: pid_t) -> i32 {
    unsafe {
        // close our sending end of the pipe
        libc::close(fds[1]);
        // open the other end of the pipe for reading
        let stream = libc::fdopen(fds[0], "r".as_ptr() as *const c_char);

        // Wait for child to send a byte via the pipe or for the pipe to be closed.
        let mut response: [u8; 1] = [0u8; 1];
        match libc::fread(response.as_mut_ptr() as *mut c_void, 1, 1, stream) {
            1 => {
                // Child sent a byte, which indicates that it succeeded and is now shutting done in
                // the background.
                0
            }
            _ => {
                // Child closed pipe without sending a byte - get the process exit_status
                let mut status: libc::c_int = -1i32;
                libc::waitpid(child_pid, &mut status, 0);
                libc::WEXITSTATUS(status)
            }
        }
    }
}

/// Create a pipe for communication between parent and child processes.
/// If successful it will return Ok and `fds` will have file descriptors for reading and writing
/// If errors it will return an error message with the errno set, if it can be read or -1 if not
fn make_pipe(fds: &mut [c_int; 2]) -> Result {
    match unsafe { libc::pipe(fds.as_mut_ptr()) } {
        0 => Ok(()),
        _ => Err(anyhow!(
            "Error creating pipe. Errno = {:?}",
            Error::last_os_error().raw_os_error().unwrap_or(-1)
        )),
    }
}
