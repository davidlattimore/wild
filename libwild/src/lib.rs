use crate::args::parse;
use args::Args;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

pub(crate) mod aarch64;
pub(crate) mod alignment;
pub(crate) mod arch;
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
pub(crate) mod part_id;
pub(crate) mod program_segments;
pub(crate) mod relaxation;
pub(crate) mod resolution;
pub(crate) mod save_dir;
pub(crate) mod sharding;
pub(crate) mod shutdown;
pub(crate) mod slice;
pub(crate) mod storage;
pub(crate) mod string_merging;
#[cfg(feature = "fork")]
pub(crate) mod subprocess;
#[cfg(not(feature = "fork"))]
#[path = "subprocess_unsupported.rs"]
pub(crate) mod subprocess;
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
pub(crate) mod x86_64;

pub use subprocess::run_in_subprocess;

pub struct Linker {
    action: args::Action,
}

impl Linker {
    pub fn from_args<S: AsRef<str>, I: Iterator<Item = S>>(args: I) -> error::Result<Self> {
        Ok(Linker {
            action: parse(args)?,
        })
    }

    pub fn run(&self) -> error::Result {
        self.run_with_callback(None)
    }

    /// Runs the linker, calling `done_closure` when linking is complete, but before cleanup is
    /// performed.
    pub(crate) fn run_with_callback(
        &self,
        done_closure: Option<Box<dyn FnOnce()>>,
    ) -> error::Result {
        match &self.action {
            args::Action::Link(args) => {
                if args.time_phases {
                    timing::init_tracing();
                } else if args.write_trace {
                    output_trace::init(args);
                } else if args.print_allocations.is_some() {
                    debug_trace::init();
                } else {
                    tracing_subscriber::registry()
                        .with(fmt::layer())
                        .with(EnvFilter::from_default_env())
                        .init();
                }
                match args.arch {
                    arch::Architecture::X86_64 => {
                        link::<storage::InMemory, x86_64::X86_64>(args, done_closure)
                    }
                    arch::Architecture::AArch64 => {
                        link::<storage::InMemory, aarch64::AArch64>(args, done_closure)
                    }
                }
            }
            args::Action::Version => {
                println!(
                    "Wild version {} (compatible with GNU linkers)",
                    env!("CARGO_PKG_VERSION")
                );
                Ok(())
            }
        }
    }

    pub fn should_fork(&self) -> bool {
        match &self.action {
            args::Action::Link(args) => args.should_fork(),
            args::Action::Version => false,
        }
    }
}

#[tracing::instrument(skip_all, name = "Link")]
fn link<S: storage::StorageModel, A: arch::Arch>(
    args: &Args,
    done_closure: Option<Box<dyn FnOnce()>>,
) -> error::Result {
    args.setup_thread_pool()?;
    let mut output = elf_writer::Output::new(args);
    let input_data = input_data::InputData::from_args(args)?;
    let inputs = archive_splitter::split_archives(&input_data)?;
    let files = parsing::parse_input_files(&inputs, args)?;
    let groups = grouping::group_files(files, args);
    let herd = bumpalo_herd::Herd::new();
    let mut symbol_db =
        symbol_db::SymbolDb::<S>::build(&groups, input_data.version_script_data.as_ref(), args)?;
    let resolved = resolution::resolve_symbols_and_sections(&groups, &mut symbol_db, &herd)?;
    let layout = layout::compute::<S, A>(&symbol_db, resolved, &mut output)?;
    let output_file = output.write::<S, A>(&layout)?;
    diff::maybe_diff()?;

    let scope = tracing::info_span!("Shutdown");
    let _scope = scope.enter();
    shutdown::free_output(output_file);
    // If there is a parent process waiting on this, inform it that linking is done and output ready
    if let Some(done_callback) = done_closure {
        done_callback();
    }
    shutdown::free_layout(layout);
    shutdown::free_symbol_db(symbol_db);
    shutdown::free_input_data(input_data);
    Ok(())
}
