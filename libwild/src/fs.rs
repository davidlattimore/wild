use crate::error::Result;
use std::fs::File;

#[inline(always)]
#[cfg(windows)]
/// On Windows, we don't need to do anything special to make a file executable.
pub(crate) fn make_executable(_: &File) -> Result {
    Ok(())
}

#[inline(always)]
#[cfg(unix)]
pub(crate) fn make_executable(file: &File) -> Result {
    use std::os::unix::prelude::PermissionsExt;

    let mut permissions = file.metadata()?.permissions();
    let mut mode = PermissionsExt::mode(&permissions);
    // Set execute permission wherever we currently have read permission.
    mode = mode | ((mode & 0o444) >> 2);
    PermissionsExt::set_mode(&mut permissions, mode);
    file.set_permissions(permissions)?;
    Ok(())
}
