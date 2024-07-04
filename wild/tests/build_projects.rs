use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

const PROJECTS_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/projects");
const WILD_TEST_DIR: &str = "wild_project_tests";
const RUSTFLAGS_LINK_WITH_WILD: &str = concat!(
    "-Clinker=clang -Clink-args=--ld-path=",
    env!("CARGO_BIN_EXE_wild")
);

#[test]
fn run_bevy_dynamic() {
    let proj_name = "bevy_dynamic";

    let proj_root = PathBuf::from(PROJECTS_ROOT).join(proj_name);

    let temp_dir = std::env::temp_dir().join(WILD_TEST_DIR).join(proj_name);

    force_copy_dir(proj_root, &temp_dir).unwrap();

    let mut cargo_cmd = Command::new("cargo");
    cargo_cmd
        .env("RUSTFLAGS", RUSTFLAGS_LINK_WITH_WILD)
        .current_dir(&temp_dir)
        .arg("run");

    let status_code = cargo_cmd.status().unwrap().code().unwrap();

    assert_eq!(status_code, 42);
}

fn force_copy_dir(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
    // TODO: uncomment remove_dir_all. Currently commented to improve iteration speed of setting up the test
    // TODO: use incremental=false once the test is stable to cut down compile time

    // let _ = fs::remove_dir_all(&dst);

    fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> io::Result<()> {
        fs::create_dir_all(&dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
            } else {
                fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
            }
        }
        Ok(())
    }

    copy_dir_all(src, dst)
}
