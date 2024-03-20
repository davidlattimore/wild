use wild_lib::*;

fn main() -> wild_lib::error::Result {
    let args = args::Args::from_env()?;
    timing::init_tracing(&args);
    link(&args)
}

#[tracing::instrument(skip_all, name = "Link")]
fn link(args: &args::Args) -> wild_lib::error::Result {
    args.setup_thread_pool()?;
    let mut output = elf_writer::Output::new(args);
    let input_data = input_data::InputData::from_args(args)?;
    let inputs = archive_splitter::split_archives(&input_data)?;
    let (mut symbol_db, files) = symbol_db::SymbolDb::build(&inputs, args)?;
    let (resolved_files, output_sections) =
        resolution::resolve_symbols_and_sections(files, &mut symbol_db)?;
    let layout = layout::compute(&symbol_db, resolved_files, output_sections, &mut output)?;
    output.write(&layout)?;

    let scope = tracing::span!(tracing::Level::INFO, "Shutdown");
    let _scope = scope.enter();
    shutdown::free_layout(layout);
    shutdown::free_symbol_db(symbol_db);
    shutdown::free_input_data(input_data);
    Ok(())
}
