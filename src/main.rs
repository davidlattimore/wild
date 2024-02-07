mod alignment;
mod archive;
mod args;
mod elf;
mod elf_writer;
mod error;
mod file_kind;
mod fs;
mod input_data;
mod layout;
mod linker_script;
mod output_section_id;
mod output_section_map;
mod output_section_part_map;
mod program_segments;
mod resolution;
mod save_dir;
mod slice;
mod symbol;
mod symbol_db;
mod timing;

fn main() -> crate::error::Result {
    let args = args::Args::from_env()?;
    args.setup_thread_pool()?;
    let mut timing = args.timing();
    let input_data = input_data::InputData::from_args(&args, &mut timing)?;
    let (mut symbol_db, file_states) = symbol_db::SymbolDb::build(&input_data, &mut timing)?;
    let (resolved_files, output_sections) =
        resolution::resolve_symbols_and_sections(file_states, &mut symbol_db, &mut timing)?;
    let layout = layout::compute(&symbol_db, resolved_files, output_sections, &mut timing)?;
    let mut output = elf_writer::Output::create(&args.output, &layout, &mut timing)?;
    elf_writer::write(&mut output, &layout, &mut timing)?;
    output.make_executable()?;
    Ok(())
}
