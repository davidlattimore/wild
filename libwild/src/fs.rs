use crate::error::Result;
use std::fs::File;
use std::path::PathBuf;

pub(crate) fn make_executable(_file: &File) -> Result {
    #[cfg(unix)]
    {
        use std::os::unix::prelude::PermissionsExt;
        let mut permissions = _file.metadata()?.permissions();
        let mut mode = PermissionsExt::mode(&permissions);
        // Set execute permission wherever we currently have read permission.
        mode = mode | ((mode & 0o444) >> 2);
        PermissionsExt::set_mode(&mut permissions, mode);
        _file.set_permissions(permissions)?;
        Ok(())
    }

    #[cfg(windows)]
    {
        Ok(())
    }
}

pub(crate) fn path_from_bytes(bytes: &[u8]) -> PathBuf {
    #[cfg(unix)]
    {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;
        std::path::Path::new(OsStr::from_bytes(bytes)).to_path_buf()
    }

    #[cfg(windows)]
    {
        use std::path::PathBuf;
        let path = std::str::from_utf8(bytes).expect("Invalid UTF-8 in archive path name");
        PathBuf::from(path)
    }
}
