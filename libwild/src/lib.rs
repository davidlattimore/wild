pub(crate) mod alignment;
pub(crate) mod arch;
pub(crate) mod archive;
pub mod args;
pub(crate) mod debug_trace;
pub(crate) mod diagnostics;
pub(crate) mod diff;
pub(crate) mod dwarf_address_info;
pub(crate) mod elf;
pub(crate) mod elf_aarch64;
pub(crate) mod elf_loongarch64;
pub(crate) mod elf_riscv64;
pub(crate) mod elf_writer;
pub(crate) mod elf_x86_64;
pub mod error;
pub(crate) mod export_list;
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
#[cfg_attr(not(feature = "plugins"), path = "linker_plugins_disabled.rs")]
mod linker_plugins;
pub(crate) mod linker_script;
pub(crate) mod output_kind;
pub(crate) mod output_section_id;
pub(crate) mod output_section_map;
pub(crate) mod output_section_part_map;
pub(crate) mod output_trace;
pub(crate) mod parsing;
pub(crate) mod part_id;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) mod perf;
#[cfg(any(
    not(target_os = "linux"),
    all(
        target_os = "linux",
        any(target_arch = "riscv64", target_arch = "loongarch64")
    )
))]
#[path = "perf_unsupported.rs"]
pub(crate) mod perf;
pub(crate) mod platform;
pub(crate) mod program_segments;
pub(crate) mod resolution;
pub(crate) mod save_dir;
pub(crate) mod sframe;
pub(crate) mod sharding;
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
pub(crate) mod value_flags;
pub(crate) mod verification;
pub(crate) mod version_script;

use crate::args::ActivatedArgs;
use crate::error::Context;
use crate::error::Result;
use crate::identity::linker_identity;
use crate::layout_rules::LayoutRulesBuilder;
use crate::output_kind::OutputKind;
use crate::platform::Platform;
use crate::value_flags::PerSymbolFlags;
use crate::version_script::VersionScript;
pub use args::Args;
use colosseum::sync::Arena;
use crossbeam_utils::atomic::AtomicCell;
use error::AlreadyInitialised;
use input_data::FileLoader;
use input_data::InputFile;
use input_data::InputLinkerScript;
use layout_rules::LayoutRules;
use output_section_id::OutputSections;
use std::io::BufWriter;
use std::io::Write;
use std::path::Path;
pub use subprocess::run_in_subprocess;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Runs the linker and cleans up associated resources. Only use this function if you've OK with
/// waiting for cleanup.
pub fn run(args: Args) -> error::Result {
    // Note, we need to setup tracing before we activate the thread pool. In particular, we need to
    // initialise the timing module before the worker threads are started, otherwise the threads
    // won't contribute to counters such as --time=cycles,instructions etc.
    setup_tracing(&args)?;
    let args = args.activate_thread_pool()?;
    let linker = Linker::new();
    linker.run(&args)?;
    drop(linker);
    timing::finalise_perfetto_trace()?;
    Ok(())
}

/// Sets up whatever tracing, if any, is indicated by the supplied arguments. This can only be
/// called once and only if nothing else has already set the global tracing dispatcher. Calling this
/// is optional. If it isn't called, no tracing-based features will function. e.g. --time.
pub fn setup_tracing(args: &Args) -> Result<(), AlreadyInitialised> {
    if let Some(opts) = args.time_phase_options.as_ref() {
        timing::init_tracing(opts)
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
    inputs_arena: Arena<InputFile>,

    linker_plugin_arena: Arena<linker_plugins::LoadedPlugin>,

    /// Anything that doesn't need a custom Drop implementation can go in here. In practice, it's
    /// mostly just the decompressed copy of compressed string-merge sections.
    herd: bumpalo_herd::Herd,

    /// We'll fill this in when we're done linking and start shutting down. Once this is dropped,
    /// that signals the end of shutdown for the purposes of timing measurement.
    #[allow(dyn_drop)]
    shutdown_scope: AtomicCell<Vec<Box<dyn Drop>>>,

    /// A timing scope that exists for the whole time we're linking.
    #[allow(dyn_drop)]
    _link_scope: Vec<Box<dyn Drop>>,
}

pub struct LinkerOutput<'layout_inputs> {
    /// This is just here so that we defer its destruction. This allows us to (a) measure how long
    /// it takes to drop and (b) if we forked, signal our parent that we're done, then drop it in
    /// the background.
    layout: Option<layout::Layout<'layout_inputs>>,
}

impl Linker {
    pub fn new() -> Self {
        let (guard_a, guard_b) = timing_guard!("Link");

        Self {
            inputs_arena: Arena::new(),
            linker_plugin_arena: Arena::new(),
            herd: Default::default(),
            shutdown_scope: Default::default(),
            _link_scope: vec![Box::new(guard_a), Box::new(guard_b)],
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
        match args.version_mode {
            args::VersionMode::ExitAfterPrint => {
                println!("{}", linker_identity());
                return Ok(LinkerOutput { layout: None });
            }
            args::VersionMode::Verbose => {
                println!("{}", linker_identity());
                // Continue linking
            }
            args::VersionMode::None => {
                // Don't print version
            }
        }

        match args.arch {
            arch::Architecture::X86_64 => self.link_for_arch::<elf_x86_64::ElfX86_64>(args),
            arch::Architecture::AArch64 => self.link_for_arch::<elf_aarch64::ElfAArch64>(args),
            arch::Architecture::RISCV64 => self.link_for_arch::<elf_riscv64::ElfRiscV64>(args),
            arch::Architecture::LoongArch64 => {
                self.link_for_arch::<elf_loongarch64::ElfLoongArch64>(args)
            }
        }
    }

    fn link_for_arch<'data, P: Platform<'data>>(
        &'data self,
        args: &'data Args,
    ) -> error::Result<LinkerOutput<'data>> {
        let mut file_loader = input_data::FileLoader::new(&self.inputs_arena);

        // Note, we propagate errors from `link_with_input_data` after we've checked if any files
        // changed. We want inputs-changed errors to take precedence over all other errors.
        let result = self.load_inputs_and_link::<P>(&mut file_loader, args);

        file_loader.verify_inputs_unchanged()?;

        // Write dependency file after successful linking
        if result.is_ok()
            && let Some(dep_file_path) = &args.dependency_file
        {
            write_dependency_file(dep_file_path, &args.output, &file_loader.loaded_files)
                .with_context(|| {
                    format!(
                        "Failed to write dependency file `{}`",
                        dep_file_path.display()
                    )
                })?;
        }

        result
    }

    fn load_inputs_and_link<'data, P: Platform<'data>>(
        &'data self,
        file_loader: &mut FileLoader<'data>,
        args: &'data Args,
    ) -> error::Result<LinkerOutput<'data>> {
        let mut plugin =
            linker_plugins::LinkerPlugin::from_args(args, &self.linker_plugin_arena, &self.herd)?;

        let loaded = file_loader.load_inputs(&args.inputs, args, &mut plugin);

        args.save_dir.finish(file_loader, args)?;

        let loaded = loaded?;

        let output_kind = OutputKind::new(args, file_loader);

        let mut output = file_writer::Output::new(args, output_kind);

        let mut output_sections = OutputSections::with_base_address(output_kind.base_address());

        let mut layout_rules_builder = LayoutRulesBuilder::default();

        let auxiliary = input_data::AuxiliaryFiles::new(args, &self.inputs_arena)?;

        let mut symbol_db = symbol_db::SymbolDb::new(args, output_kind, &auxiliary, &self.herd)?;
        let mut per_symbol_flags = PerSymbolFlags::new();

        symbol_db.add_inputs(
            &mut per_symbol_flags,
            &mut output_sections,
            &mut layout_rules_builder,
            loaded,
        )?;

        // TODO: Doing this here means that we can't wrap symbols produced by the linker plugin.
        // Moving it earlier or later however requires some rethought as to how this works.
        symbol_db.apply_wrapped_symbol_overrides();

        let mut resolver = resolution::Resolver::default();

        resolver.resolve_symbols_and_select_archive_entries(&mut symbol_db)?;

        // Now that we know which archive entries are being loaded, we can resolve alternative
        // symbol definitions.
        crate::symbol_db::resolve_alternative_symbol_definitions(
            &mut symbol_db,
            &mut per_symbol_flags,
            &resolver.resolved_groups,
        )?;

        if let Some(plugin) = plugin.as_mut()
            && plugin.is_initialised()
        {
            plugin.all_symbols_read(
                &mut symbol_db,
                &mut resolver,
                file_loader,
                &mut per_symbol_flags,
                &mut output_sections,
                &mut layout_rules_builder,
            )?;
        }

        // If it's a rust version script, apply the global symbol visibility now.
        // We previously downgraded all symbols to local visibility.
        if let VersionScript::Rust(rust_vscript) = &symbol_db.version_script {
            symbol_db.handle_rust_version_script(rust_vscript, &mut per_symbol_flags);
        }

        let layout_rules = layout_rules_builder.build();

        let resolved = resolver.resolve_sections_and_canonicalise_undefined(
            &mut symbol_db,
            &mut per_symbol_flags,
            &mut output_sections,
            &layout_rules,
        )?;

        let layout = layout::compute::<P>(
            symbol_db,
            per_symbol_flags,
            resolved,
            output_sections,
            &mut output,
        )?;

        output.write(&layout, elf_writer::write::<P>)?;
        diff::maybe_diff()?;

        // We've finished linking. We consider everything from this point onwards as shutdown.
        let (g1, g2) = timing_guard!("Shutdown");
        self.shutdown_scope.store(vec![Box::new(g1), Box::new(g2)]);

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
        timing_phase!("Drop inputs");
        self.inputs_arena = Arena::new();
        self.herd = Default::default();
    }
}

impl Drop for LinkerOutput<'_> {
    fn drop(&mut self) {
        timing_phase!("Drop layout");
        self.layout.take();
    }
}

/// Writes a dependency file in Makefile format.
fn write_dependency_file(
    dep_file_path: &Path,
    output_path: &Path,
    loaded_files: &[&InputFile],
) -> std::io::Result<()> {
    timing_phase!("Write dependency file");

    let file = std::fs::File::create(dep_file_path)?;
    let mut writer = BufWriter::new(file);

    // Collect unique dependency paths
    let mut seen = std::collections::HashSet::new();
    let mut deps = Vec::new();
    for input_file in loaded_files {
        // Skip temporary files. e.g. those generated by linker plugins.
        if input_file.modifiers.temporary {
            continue;
        }

        let path_str = input_file.filename.display().to_string();
        if seen.insert(path_str.clone()) {
            deps.push(path_str);
        }
    }

    write!(writer, "{}:", output_path.display())?;

    for dep in &deps {
        write!(writer, " {dep}")?;
    }

    writeln!(writer)?;

    for dep in &deps {
        writeln!(writer, "\n{dep}:")?;
    }

    Ok(())
}

/// Possibly initialise timing if a timing-related environment variable is active and it was enabled
/// in the build, otherwise, do nothing. See `BENCHMARKING.md` for details.
pub fn init_timing() -> Result {
    timing::setup()
}
