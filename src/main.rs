mod alignment;
mod archive;
mod archive_splitter;
mod args;
mod elf;
mod elf_writer;
mod error;
mod file_kind;
mod fs;
mod hash;
mod identity;
mod input_data;
mod layout;
mod linker_script;
mod output_section_id;
mod output_section_map;
mod output_section_part_map;
mod program_segments;
mod resolution;
mod save_dir;
mod shutdown;
mod slice;
mod symbol;
mod symbol_db;
mod timing;

fn main() -> crate::error::Result {
    let args = args::Args::from_env()?;
    timing::init_tracing(&args);
    link(&args)
}

#[tracing::instrument(skip_all, name = "Link")]
fn link(args: &args::Args) -> crate::error::Result {
    args.setup_thread_pool()?;
    let mut output = elf_writer::Output::new(args);
    let input_data = input_data::InputData::from_args(args)?;
    let inputs = archive_splitter::split_archives(&input_data)?;
    let (mut symbol_db, file_states) = symbol_db::SymbolDb::build(&inputs, args)?;
    let (resolved_files, output_sections) =
        resolution::resolve_symbols_and_sections(file_states, &mut symbol_db)?;
    let layout = layout::compute(&symbol_db, resolved_files, output_sections, &mut output)?;
    output.write(&layout)?;

    let scope = tracing::span!(tracing::Level::INFO, "Shutdown");
    let _scope = scope.enter();
    shutdown::free_layout(layout);
    shutdown::free_symbol_db(symbol_db);
    shutdown::free_input_data(input_data);
    Ok(())
}
