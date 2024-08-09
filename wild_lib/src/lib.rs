// It's not always desirable to use if-let instead of a match, especially if you might later end up
// adding more branches to the match.
#![allow(clippy::single_match)]
// Sure, less arguments is good, but it's a trade-off. Sometimes you have a complex function that
// you'd like to split by extracting part of it out into a new function. That new function might
// have lots of arguments. It might be possible to group some of those arguments together into some
// new struct, but not always. Given the choice between a function that's too large and does too
// much vs a function that has too many arguments, it's sometimes best to pick the latter.
// Especially since that function is generally only ever called from one place and the arguments all
// have distinct types.
#![allow(clippy::too_many_arguments)]

use args::Args;

pub(crate) mod alignment;
pub(crate) mod archive;
pub(crate) mod archive_splitter;
pub mod args;
pub(crate) mod debug_trace;
pub(crate) mod diff;
pub(crate) mod elf;
pub(crate) mod elf_writer;
pub mod error;
pub(crate) mod file_kind;
pub(crate) mod fs;
pub(crate) mod gc_stats;
pub(crate) mod grouping;
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
#[cfg(not(feature = "single-threaded"))]
#[path = "threading_rayon.rs"]
pub(crate) mod threading;
#[cfg(feature = "single-threaded")]
#[path = "threading_none.rs"]
pub(crate) mod threading;
pub(crate) mod timing;
pub(crate) mod validation;
pub(crate) mod verification;

pub struct Linker {
    action: crate::args::Action,
}

impl Linker {
    pub fn from_env() -> crate::error::Result<Self> {
        Ok(Linker {
            action: crate::args::from_env()?,
        })
    }

    pub fn run(&self) -> crate::error::Result {
        match &self.action {
            args::Action::Link(args) => {
                if args.time_phases {
                    timing::init_tracing();
                } else if args.write_trace {
                    output_trace::init(args);
                } else if args.print_allocations.is_some() {
                    debug_trace::init();
                }
                link(args)
            }
            args::Action::Version => {
                println!("Wild version {}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
        }
    }
}

#[tracing::instrument(skip_all, name = "Link")]
fn link(args: &Args) -> crate::error::Result {
    args.setup_thread_pool()?;
    let mut output = elf_writer::Output::new(args);
    let input_data = input_data::InputData::from_args(args)?;
    let inputs = archive_splitter::split_archives(&input_data)?;
    let files = parsing::parse_input_files(&inputs, args)?;
    let mut symbol_db =
        symbol_db::SymbolDb::build(&files, input_data.version_script_data.as_ref(), args)?;
    let resolved = resolution::resolve_symbols_and_sections(&files, &mut symbol_db)?;
    let layout = layout::compute(&symbol_db, resolved, &mut output)?;
    let output_file = output.write(&layout)?;
    diff::maybe_diff()?;

    let scope = tracing::span!(tracing::Level::INFO, "Shutdown");
    let _scope = scope.enter();
    shutdown::free_output(output_file);
    shutdown::free_layout(layout);
    shutdown::free_symbol_db(symbol_db);
    shutdown::free_input_data(input_data);
    Ok(())
}
