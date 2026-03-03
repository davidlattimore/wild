use crate::args::Args;
use crate::bail;
use crate::error::Result;
use phnt::ffi::HANDLE;
use phnt::ffi::NtClose;
use phnt::ffi::NtCreateUserProcess;
use phnt::ffi::NtTerminateProcess;
use phnt::ffi::NtWaitForSingleObject;
use phnt::ffi::PROCESS_CREATE_FLAGS_INHERIT_HANDLES;
use phnt::ffi::PS_CREATE_INFO;
use std::ptr;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::FALSE;
use windows_sys::Win32::Foundation::STATUS_PROCESS_CLONED;
use windows_sys::Win32::Foundation::TRUE;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::Storage::FileSystem::WriteFile;
use windows_sys::Win32::System::Console::ATTACH_PARENT_PROCESS;
use windows_sys::Win32::System::Console::AttachConsole;
use windows_sys::Win32::System::Console::FreeConsole;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;
use windows_sys::Win32::System::Threading::THREAD_ALL_ACCESS;

/// Runs the linker, in a subprocess if possible, prints any errors, then exits.
///
/// This is done by forking a sub-process which runs the linker and waits for communication back
/// from the sub-process (via a pipe) when the main link task is done (the output file has been
/// written, but some shutdown tasks remain.
///
/// Don't call `setup_tracing` or `setup_thread_pool` if using this function, these will be called
/// for you in the subprocess.
///
/// # Safety
/// Must not be called once threads have been spawned. Calling this function from main is generally
/// the best way to ensure this.
pub unsafe fn run_in_subprocess(args: Args) -> ! {
    let exit_code = match subprocess_result(args) {
        Ok(code) => code,
        Err(error) => crate::error::report_error_and_exit(&error),
    };
    std::process::exit(exit_code);
}

#[allow(non_upper_case_globals)]
pub const NtCurrentProcess: HANDLE = -1isize as *mut std::ffi::c_void;

fn subprocess_result(args: Args) -> Result<i32> {
    let (read_end, write_end) = make_pipe()?;

    let mut hprocess: HANDLE = std::ptr::null_mut();
    let mut hthread: HANDLE = std::ptr::null_mut();

    match unsafe { fork(&mut hprocess, &mut hthread) } {
        STATUS_PROCESS_CLONED => {
            // executing inside the clone

            // re attach to the parent's console to be able to write to it
            unsafe {
                FreeConsole();
                AttachConsole(ATTACH_PARENT_PROCESS);
            };

            crate::setup_tracing(&args)?;
            let args = args.activate_thread_pool()?;
            let linker = crate::Linker::new();
            linker.run(args)?;
            inform_parent_done(write_end);
            unsafe { NtTerminateProcess(NtCurrentProcess, STATUS_PROCESS_CLONED) };
            Ok(0)
        }
        0 => {
            let exit_status = wait_for_child_done(read_end, hprocess, hthread);
            Ok(exit_status)
        }
        _ => {
            // Fork failure in the parent - Fallback to running linker in this process
            crate::run(args)?;
            Ok(0)
        }
    }
}

fn inform_parent_done(write_end: HANDLE) {
    let mut bytes_written = 0;

    unsafe {
        WriteFile(
            write_end,
            "X".as_ptr(),
            1,
            &mut bytes_written,
            std::ptr::null_mut(),
        );
        CloseHandle(write_end);
        FreeConsole();
    }
}

fn wait_for_child_done(read_end: HANDLE, hprocess: HANDLE, hthread: HANDLE) -> i32 {
    let mut response: [u8; 1] = [0u8; 1];
    let mut bytes_read = 0;
    match unsafe {
        ReadFile(
            read_end,
            response.as_mut_ptr(),
            1,
            &mut bytes_read,
            std::ptr::null_mut(),
        )
    } {
        TRUE => {
            // Child sent a byte, which indicates that it succeeded and is now shutting down in
            // the background.
            0
        }
        _ => {
            // Child closed pipe without sending a byte - get the process exit_status
            let status = unsafe { NtWaitForSingleObject(hprocess, FALSE as _, ptr::null_mut()) };
            unsafe {
                NtClose(hprocess);
                NtClose(hthread);
            };
            status
        }
    }
}

unsafe fn fork(hprocess: &mut HANDLE, hthread: &mut HANDLE) -> i32 {
    let mut create_info: PS_CREATE_INFO = unsafe { std::mem::zeroed() };
    create_info.Size = std::mem::size_of::<PS_CREATE_INFO>() as _;

    unsafe {
        NtCreateUserProcess(
            hprocess,
            hthread,
            PROCESS_ALL_ACCESS,
            THREAD_ALL_ACCESS,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
            0,
            std::ptr::null_mut(),
            &mut create_info,
            std::ptr::null_mut(),
        )
    }
}

fn make_pipe() -> Result<(HANDLE, HANDLE)> {
    let mut read_end: HANDLE = std::ptr::null_mut();
    let mut write_end: HANDLE = std::ptr::null_mut();

    let security_attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: TRUE, // The crucial part!
    };

    match unsafe { CreatePipe(&mut read_end, &mut write_end, &security_attributes, 0) } {
        TRUE => Ok((read_end, write_end)),
        _ => bail!(
            "Error creating pipe. Errno = {:?}",
            std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        ),
    }
}
