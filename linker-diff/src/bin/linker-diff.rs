fn main() -> anyhow::Result<()> {
    linker_diff::enable_diagnostics();

    let config = linker_diff::Config::from_env();
    let report = linker_diff::Report::from_config(config)?;

    if report.has_problems() {
        println!("{report}");
        std::process::exit(1);
    } else {
        println!("No differences or validation failures detected");
    }

    Ok(())
}
