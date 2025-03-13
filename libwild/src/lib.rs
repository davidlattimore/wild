use crate::args::parse;
use args::Args;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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
pub(crate) mod resolution;
pub(crate) mod save_dir;
pub(crate) mod sharding;
pub(crate) mod shutdown;
pub(crate) mod slice;
pub(crate) mod string_merging;
#[cfg(feature = "fork")]
pub(crate) mod subprocess;
#[cfg(not(feature = "fork"))]
#[path = "subprocess_unsupported.rs"]
pub(crate) mod subprocess;
pub(crate) mod symbol;
pub(crate) mod symbol_db;
pub(crate) mod timing;
pub(crate) mod validation;
pub(crate) mod verification;
pub(crate) mod x86_64;

use error::AlreadyInitialised;
use input_data::InputData;
pub use subprocess::run_in_subprocess;

pub struct Linker {
    args: Args,
}

impl Linker {
    pub fn from_args<S: AsRef<str>, I: Iterator<Item = S>>(args: I) -> error::Result<Self> {
        Ok(Linker { args: parse(args)? })
    }

    /// Sets up whatever tracing, if any, is indicated by the supplied arguments. This can only be
    /// called once and only if nothing else has already set the global tracing dispatcher. Calling
    /// this is optional. If it isn't called, no tracing-based features will function. e.g. --time,
    /// writing .trace files etc.
    pub fn setup_tracing(&self) -> Result<(), AlreadyInitialised> {
        let args = &self.args;
        if args.time_phases {
            timing::init_tracing()
        } else if args.print_allocations.is_some() {
            debug_trace::init()
        } else {
            tracing_subscriber::registry()
                .with(fmt::layer())
                .with(EnvFilter::from_default_env())
                .try_init()
                .map_err(|_| AlreadyInitialised)
        }
    }

    /// Sets up the global thread pool based on the supplied arguments, in particular --threads.
    /// This can only be called once. Calling this at all is optional. If it isn't called, then a
    /// default thread pool will be used - i.e. any argument to --threads will be ignored.
    pub fn setup_thread_pool(&self) -> error::Result {
        self.args.setup_thread_pool()
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
        let args = &self.args;
        if args.should_print_version {
            println!(
                "Wild version {} (compatible with GNU linkers)",
                env!("CARGO_PKG_VERSION")
            );
            if args.inputs.is_empty() {
                return Ok(());
            }
        }
        match args.arch {
            arch::Architecture::X86_64 => link::<x86_64::X86_64>(args, done_closure),
            arch::Architecture::AArch64 => link::<aarch64::AArch64>(args, done_closure),
        }
    }

    pub fn should_fork(&self) -> bool {
        self.args.should_fork()
    }
}

#[tracing::instrument(skip_all, name = "Link")]
fn link<A: arch::Arch>(args: &Args, done_closure: Option<Box<dyn FnOnce()>>) -> error::Result {
    let shutdown_span = tracing::info_span!("Shutdown");
    let output = elf_writer::Output::new(args);
    let input_data = input_data::InputData::from_args(args)?;

    // Note, we propagate errors from `link_with_input_data` after we've checked if any files
    // changed. We want inputs-changed errors to take precedence over all other errors.
    let result = link_with_input_data::<A>(output, &input_data, args, done_closure, &shutdown_span);
    input_data.verify_inputs_unchanged()?;
    let _shutdown_scope = result?;

    shutdown::free_input_data(input_data);

    Ok(())
}

fn link_with_input_data<'shutdown_span, A: arch::Arch>(
    mut output: elf_writer::Output,
    input_data: &InputData,
    args: &Args,
    done_closure: Option<Box<dyn FnOnce()>>,
    shutdown_span: &'shutdown_span tracing::Span,
) -> error::Result<tracing::span::Entered<'shutdown_span>> {
    let inputs = archive_splitter::split_archives(input_data)?;
    let files = parsing::parse_input_files(&inputs, args)?;
    let groups = grouping::group_files(files, args);
    let herd = bumpalo_herd::Herd::new();
    let mut symbol_db =
        symbol_db::SymbolDb::build(&groups, input_data.version_script_data.as_ref(), args)?;
    let resolved = resolution::resolve_symbols_and_sections(&groups, &mut symbol_db, &herd)?;
    let layout = layout::compute::<A>(symbol_db, resolved, &mut output)?;
    let output_file = output.write::<A>(&layout)?;
    diff::maybe_diff()?;

    let shutdown_scope = shutdown_span.enter();
    shutdown::free_output(output_file);
    // If there is a parent process waiting on this, inform it that linking is done and output ready
    if let Some(done_callback) = done_closure {
        done_callback();
    }
    shutdown::free_layout(layout);

    Ok(shutdown_scope)
}
