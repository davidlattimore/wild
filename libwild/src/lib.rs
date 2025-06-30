pub(crate) mod aarch64;
pub(crate) mod alignment;
pub(crate) mod arch;
pub(crate) mod archive;
pub mod args;
pub(crate) mod debug_trace;
pub(crate) mod diagnostics;
pub(crate) mod diff;
pub(crate) mod dwarf_address_info;
pub(crate) mod elf;
pub(crate) mod elf_writer;
pub mod error;
pub(crate) mod file_kind;
pub(crate) mod file_writer;
pub(crate) mod fs;
pub(crate) mod gc_stats;
pub(crate) mod grouping;
pub(crate) mod hash;
pub(crate) mod identity;
pub(crate) mod input_data;
pub(crate) mod layout;
pub(crate) mod layout_rules;
pub(crate) mod linker_script;
pub(crate) mod output_section_id;
pub(crate) mod output_section_map;
pub(crate) mod output_section_part_map;
pub(crate) mod output_trace;
pub(crate) mod parsing;
pub(crate) mod part_id;
pub(crate) mod program_segments;
pub(crate) mod resolution;
pub(crate) mod riscv64;
pub(crate) mod save_dir;
pub(crate) mod sharding;
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
pub(crate) mod version_script;
pub(crate) mod x86_64;

use crate::args::ActivatedArgs;
pub use args::Args;
use colosseum::sync::Arena;
use crossbeam_utils::atomic::AtomicCell;
use error::AlreadyInitialised;
use input_data::InputData;
use input_data::InputFile;
use input_data::InputLinkerScript;
use layout_rules::LayoutRules;
use output_section_id::OutputSections;
use std::sync::atomic::Ordering;
pub use subprocess::run_in_subprocess;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Runs the linker and cleans up associated resources. Only use this function if you've OK with
/// waiting for cleanup.
pub fn run(args: Args) -> error::Result {
    setup_tracing(&args)?;
    let args = args.activate_thread_pool()?;
    let linker = Linker::new();
    linker.run(&args)?;
    Ok(())
}

/// Sets up whatever tracing, if any, is indicated by the supplied arguments. This can only be
/// called once and only if nothing else has already set the global tracing dispatcher. Calling this
/// is optional. If it isn't called, no tracing-based features will function. e.g. --time.
pub fn setup_tracing(args: &Args) -> Result<(), AlreadyInitialised> {
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

/// This is effectively a data store for use while linking. It takes ownership of all the input data
/// that we read, which allows the linking stages to borrow that data. Dropping this struct might be
/// expensive, so the caller of the linker might want to think about when best to drop it - probably
/// together with the `LinkerOutput`. Note, calling `exit` without dropping this struct is an
/// option, but likely won't save any time, since the bulk of the work done during drop (unmapping
/// pages) will still happen anyway.
pub struct Linker {
    /// We store our input files here once we've read them.
    inputs: Arena<InputFile>,

    /// Anything that doesn't need a custom Drop implementation can go in here. In practice, it's
    /// mostly just the decompressed copy of compressed string-merge sections.
    herd: bumpalo_herd::Herd,

    /// We'll fill this in when we're done linking and start shutting down. Once this is dropped,
    /// that signals the end of shutdown for the purposes of timing measurement.
    shutdown_scope: AtomicCell<Option<Box<tracing::span::EnteredSpan>>>,

    /// A timing scope that exists for the whole time we're linking.
    _link_scope: tracing::span::EnteredSpan,
}

pub struct LinkerOutput<'layout_inputs> {
    /// This is just here so that we defer its destruction. This allows us to (a) measure how long
    /// it takes to drop and (b) if we forked, signal our parent that we're done, then drop it in
    /// the background.
    layout: Option<layout::Layout<'layout_inputs>>,
}

impl Linker {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inputs: Arena::new(),
            herd: Default::default(),
            shutdown_scope: Default::default(),
            _link_scope: tracing::info_span!("Link").entered(),
        }
    }

    /// Runs the linker. The returned value isn't useful for anything, but is somewhat expensive to
    /// drop, so we leave it up to the caller to decide when to drop it. At the point at which we
    /// return, the output file should be usable.
    pub fn run<'layout_inputs>(
        &'layout_inputs self,
        args: &'layout_inputs ActivatedArgs,
    ) -> error::Result<LinkerOutput<'layout_inputs>> {
        let args = &args.args;
        if args.should_print_version {
            println!(
                "Wild version {} (compatible with GNU linkers)",
                env!("CARGO_PKG_VERSION")
            );
            if args.inputs.is_empty() {
                return Ok(LinkerOutput { layout: None });
            }
        }

        match args.arch {
            arch::Architecture::X86_64 => self.link_for_arch::<x86_64::X86_64>(args),
            arch::Architecture::AArch64 => self.link_for_arch::<aarch64::AArch64>(args),
            arch::Architecture::RISCV64 => self.link_for_arch::<riscv64::RiscV64>(args),
        }
    }

    fn link_for_arch<'layout_inputs, A: arch::Arch>(
        &'layout_inputs self,
        args: &'layout_inputs Args,
    ) -> error::Result<LinkerOutput<'layout_inputs>> {
        let output = file_writer::Output::new(args);

        let input_data = input_data::InputData::from_args(args, &self.inputs)?;

        // Note, we propagate errors from `link_with_input_data` after we've checked if any files
        // changed. We want inputs-changed errors to take precedence over all other errors.
        let result = self.link_with_input_data::<A>(output, &input_data, args);

        input_data.verify_inputs_unchanged()?;

        result
    }

    fn link_with_input_data<'data, A: arch::Arch>(
        &'data self,
        mut output: file_writer::Output,
        input_data: &InputData<'data>,
        args: &'data Args,
    ) -> error::Result<LinkerOutput<'data>> {
        let mut output_sections = OutputSections::with_base_address(args.base_address());

        if args.output_kind().is_static_executable()
            && input_data
                .inputs
                .iter()
                .any(|input| input.kind == crate::file_kind::FileKind::ElfDynamic)
        {
            args.is_dynamic_executable.store(true, Ordering::Relaxed);
        }

        let (linker_scripts, layout_rules) =
            parsing::process_linker_scripts(&input_data.linker_scripts, &mut output_sections)?;

        let parsed_inputs = parsing::parse_input_files(&input_data.inputs, linker_scripts, args)?;

        let groups = grouping::group_files(parsed_inputs, args, &self.herd);

        let mut symbol_db = symbol_db::SymbolDb::build(
            groups,
            input_data.version_script_data,
            args,
            &input_data.linker_scripts,
        )?;

        let resolved = resolution::resolve_symbols_and_sections(
            &mut symbol_db,
            &self.herd,
            &mut output_sections,
            &layout_rules,
        )?;

        let layout = layout::compute::<A>(
            symbol_db,
            resolved,
            output_sections,
            &mut output,
            input_data,
        )?;

        output.write(&layout, elf_writer::write::<A>)?;
        diff::maybe_diff()?;

        // We've finished linking. We consider everything from this point onwards as shutdown.
        let shutdown_span = tracing::info_span!("Shutdown");
        self.shutdown_scope
            .store(Some(Box::new(shutdown_span.entered())));

        Ok(LinkerOutput {
            layout: Some(layout),
        })
    }
}

impl Default for Linker {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Linker {
    fn drop(&mut self) {
        let _span = tracing::info_span!("Drop inputs").entered();
        self.inputs = Arena::new();
        self.herd = Default::default();
    }
}

impl Drop for LinkerOutput<'_> {
    fn drop(&mut self) {
        let _span = tracing::info_span!("Drop layout").entered();
        self.layout.take();
    }
}
