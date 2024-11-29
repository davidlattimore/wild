use anyhow::anyhow;
use anyhow::Context;
use libc::fork;
use libc::pid_t;
use std::env::args;
use std::ffi::c_int;
use std::ffi::c_void;
use std::io::Error;
use std::process;

/// Run the linker with the supplied arguments.
///
/// This implements an optimization to remove the time taken for some shutdown tasks from the time
/// taken for *this* process to complete.
///
/// This is done by forking a sub-process which runs the linker and waiting for communication
/// back from the sub-process (via a pipe) when the main link task is done (the output file has
/// been written, but some shutdown tasks remain).
fn main() -> wild_lib::error::Result {
    let linker = wild_lib::Linker::from_args(args().skip(1))?;

    if !linker.should_fork() {
        // Run the linker in this process without forking.
        return linker.run(None);
    }

    let mut fds: [c_int; 2] = [0; 2];
    // create the pipe used to communicate between the parent and child processes - exit on failure
    make_pipe(&mut fds).context("make_pipe")?;

    match unsafe { fork() } {
        0 => {
            // Fork success in child - Run linker in this process.
            let done_closure = move |exit_status: i32| inform_parent_done(&fds, exit_status);
            linker.run(Some(Box::new(done_closure)))
        }
        -1 => {
            // Fork failure in the parent - Fallback to running linker in this process
            linker.run(None)
        }
        pid => {
            // Fork success in the parent - wait for the child to "signal" us it's done
            let exit_status = wait_for_child_done(&fds, pid);
            process::exit(exit_status);
        }
    }
}

/// Inform the parent process that work of linker is done, sending the exit status over the pipe
fn inform_parent_done(fds: &[c_int], exit_status: i32) {
    unsafe {
        libc::close(fds[0]);
        let stream = libc::fdopen(fds[1], "w".as_ptr() as *const i8);
        let bytes: [u8; 4] = exit_status.to_ne_bytes();
        libc::fwrite(bytes.as_ptr() as *const c_void, 4, 1, stream);
        libc::fclose(stream);
        libc::close(libc::STDOUT_FILENO);
        libc::close(libc::STDERR_FILENO);
    }
}

/// Wait for the child process to signal it is done, by returning an exit code on the pipe.
/// In the case the child crashes, or exits via some path that doesn't explicitly return (early)
/// an exit status, then the pipe will be closed and `freed` will return -1.
/// In that case, we get the child exit status by waiting for (or ensuring) it's death, and we
/// return the child's exit status from `waitpid`
fn wait_for_child_done(fds: &[c_int], child_pid: pid_t) -> i32 {
    unsafe {
        // close our sending end of the pipe
        libc::close(fds[1]);
        // open the other end of the pipe for reading
        let stream = libc::fdopen(fds[0], "r".as_ptr() as *const i8);

        // Wait for child to send exit_status or pipe to be closed
        let mut response: [u8; 4] = [0u8; 4];
        match libc::fread(response.as_mut_ptr() as *mut c_void, 1, 4, stream) {
            4 => {
                // Child sent an exit status early - to allow us to exit before it performs shutdown
                i32::from_ne_bytes(response)
            }
            _ => {
                // Child closed pipe without sending an exit status - get the process exit_status
                let mut child_exit_status = -1i32;
                libc::waitpid(child_pid, &mut child_exit_status as *mut c_int, 0);
                child_exit_status
            }
        }
    }
}

/// Create a pipe for communication between parent and child processes.
/// If successful it will return Ok and `fds` will have file descriptors for reading and writing
/// If errors it will return an error message with the errno set, if it can be read or -1 if not
fn make_pipe(fds: &mut [c_int; 2]) -> wild_lib::error::Result<()> {
    match unsafe { libc::pipe(fds.as_mut_ptr()) } {
        0 => Ok(()),
        _ => Err(anyhow!(
            "Error creating pipe. Errno = {:?}",
            Error::last_os_error().raw_os_error().unwrap_or(-1)
        )),
    }
}
