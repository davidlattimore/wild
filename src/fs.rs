use crate::error::Result;
use std::fs::File;

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
