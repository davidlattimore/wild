fn main() -> wild_lib::error::Result {
    let linker = wild_lib::Linker::from_env()?;
    linker.run()
}
