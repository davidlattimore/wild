#![allow(clippy::needless_update)]
#![allow(clippy::match_like_matches_macro)]
#![allow(clippy::single_match)]

pub(crate) mod alignment;
pub(crate) mod archive;
pub(crate) mod archive_splitter;
pub mod args;
pub(crate) mod elf;
pub(crate) mod elf_writer;
pub mod error;
pub(crate) mod file_kind;
pub(crate) mod fs;
pub(crate) mod hash;
pub(crate) mod identity;
pub(crate) mod input_data;
pub(crate) mod layout;
pub(crate) mod linker_script;
pub(crate) mod output_section_id;
pub(crate) mod output_section_map;
pub(crate) mod output_section_part_map;
pub(crate) mod output_trace;
pub(crate) mod parsing;
pub(crate) mod program_segments;
pub(crate) mod relaxation;
pub(crate) mod resolution;
pub(crate) mod save_dir;
pub(crate) mod sharding;
pub(crate) mod shutdown;
pub(crate) mod slice;
pub(crate) mod symbol;
pub(crate) mod symbol_db;
pub(crate) mod timing;
pub(crate) mod validation;

pub struct Linker {
    args: crate::args::Args,
}

impl Linker {
    pub fn from_env() -> crate::error::Result<Self> {
        Ok(Linker {
            args: crate::args::Args::from_env()?,
        })
    }

    pub fn run(&self) -> crate::error::Result {
        if self.args.time_phases {
            timing::init_tracing();
        } else if self.args.write_trace {
            output_trace::init(&self.args);
        }
        self.link()
    }

    #[tracing::instrument(skip_all, name = "Link")]
    fn link(&self) -> crate::error::Result {
        self.args.setup_thread_pool()?;
        let mut output = elf_writer::Output::new(&self.args);
        let input_data = input_data::InputData::from_args(&self.args)?;
        let inputs = archive_splitter::split_archives(&input_data)?;
        let files = parsing::parse_input_files(&inputs, &self.args)?;
        let mut symbol_db =
            symbol_db::SymbolDb::build(&files, &input_data.version_script, &self.args)?;
        let (resolved_files, output_sections) =
            resolution::resolve_symbols_and_sections(&files, &mut symbol_db)?;
        let layout = layout::compute(&symbol_db, resolved_files, output_sections, &mut output)?;
        output.write(&layout)?;

        let scope = tracing::span!(tracing::Level::INFO, "Shutdown");
        let _scope = scope.enter();
        shutdown::free_layout(layout);
        shutdown::free_symbol_db(symbol_db);
        shutdown::free_input_data(input_data);
        Ok(())
    }
}
