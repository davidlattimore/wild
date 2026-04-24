pub(crate) mod alignment;
pub use args::Args;
pub(crate) mod arch;
pub(crate) mod archive;
pub mod args;
pub(crate) mod debug_trace;
pub(crate) mod diagnostics;
pub(crate) mod diff;
pub(crate) mod dwarf_address_info;
pub(crate) mod eh_frame;
pub(crate) mod elf;
pub(crate) mod elf_aarch64;
pub(crate) mod elf_abbrev_dedup;
pub(crate) mod elf_compress;
pub(crate) mod elf_line_v5;
pub(crate) mod elf_loongarch64;
pub(crate) mod elf_riscv64;
pub(crate) mod elf_writer;
pub(crate) mod elf_x86_64;
pub mod error;
pub(crate) mod export_list;
pub(crate) mod expression_eval;
pub(crate) mod file_kind;
pub(crate) mod file_writer;
pub(crate) mod fs;
pub(crate) mod gc_stats;
pub(crate) mod glob_match;
pub(crate) mod grouping;
pub(crate) mod hash;
pub(crate) mod incremental_cache;
pub(crate) mod input_data;
pub(crate) mod layout;
pub(crate) mod layout_rules;
pub(crate) mod sdk_cache;
pub(crate) mod suffix_share;
// The ELF Gold-plugin LTO code lives physically under `lto/` as part
// of the LtoDriver family (see `wild-lto-plan.md`). The `mod
// linker_plugins` alias is kept so existing callers continue to use
// `crate::linker_plugins::…`; a follow-up commit mass-renames them.
#[cfg_attr(feature = "plugins", path = "lto/elf_gold.rs")]
#[cfg_attr(not(feature = "plugins"), path = "lto/elf_gold_disabled.rs")]
mod linker_plugins;
pub(crate) mod linker_script;
pub mod llvm_tools;
pub(crate) mod lto;
pub(crate) mod macho;
pub(crate) mod macho_aarch64;
pub(crate) mod macho_codesign;
#[cfg(feature = "macho-lto")]
pub(crate) mod macho_lto;
pub(crate) mod macho_writer;
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
#[cfg(all(feature = "fork", unix))]
pub(crate) mod subprocess;
#[cfg(not(all(feature = "fork", unix)))]
#[path = "subprocess_unsupported.rs"]
pub(crate) mod subprocess;
pub(crate) mod symbol;
pub(crate) mod symbol_db;
#[cfg(all(test, not(target_family = "wasm")))]
mod tidy_tests;
pub(crate) mod timing;
pub(crate) mod validation;
pub(crate) mod value_flags;
pub(crate) mod verification;
pub(crate) mod version_script;
pub(crate) mod wasm;
pub(crate) mod wasm_arch;
pub(crate) mod wasm_writer;

use crate::elf::Elf;
use crate::error::Context;
use crate::error::Result;
use crate::layout_rules::LayoutRulesBuilder;
use crate::macho::MachO;
use crate::output_kind::OutputKind;
use crate::platform::Arch;
use crate::platform::Args as _;
use crate::platform::Platform;
use crate::value_flags::PerSymbolFlags;
use crate::version_script::VersionScript;
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
pub fn run(mut args: Args) -> error::Result {
    let thread_pool = args.common_mut().activate_thread_pool()?;
    let linker = Linker::new();
    linker.run(&args, &thread_pool)?;
    drop(linker);
    timing::finalise_perfetto_trace()?;
    Ok(())
}

/// Super-early skip check — called from `main()` BEFORE
/// `Args::parse` and BEFORE the fork dispatch. Only reads `argv`
/// and the cache side-car; does no library-path resolution.
///
/// On a rust-analyzer link the full arg parser takes ~274 ms
/// (walks `-L`, resolves every `-l`, probes the SDK). This
/// function deliberately bypasses all of that — on a cache hit
/// the skip cost is dominated by the 229-path fingerprint verify,
/// not by arg parsing.
///
/// Gated on `WILD_INCREMENTAL_DEBUG=1`; with the env var unset,
/// returns `false` without reading any files.
pub fn try_early_skip_from_argv() -> Option<std::path::PathBuf> {
    if std::env::var_os("WILD_INCREMENTAL_DEBUG").is_none() {
        return None;
    }
    if std::env::var_os("WILD_INCREMENTAL_NO_EARLY_SKIP").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return None;
    }
    let argv: Vec<String> = std::env::args().collect();
    let output = incremental_cache::extract_output_path(&argv);
    let args_hash = incremental_cache::compute_args_hash(&argv);
    let hashes_path = incremental_cache::hashes_path_for_output(&output);
    let Some(cached) = incremental_cache::read_link_cache(&hashes_path) else {
        return None;
    };
    if cached.wild_version != incremental_cache::WILD_VERSION || cached.args_hash != args_hash {
        return None;
    }
    if incremental_cache::verify_cached_inputs_unchanged(&cached.inputs).is_none() {
        return None;
    }
    match std::fs::metadata(&output) {
        Ok(m) if m.len() == cached.output_size => {
            eprintln!(
                "wild incremental: EARLY SKIP (pre-argparse) — output at {} \
                 reused",
                output.display()
            );
            Some(output)
        }
        _ => None,
    }
}

/// Keep the old signature-check for callers that already have a
/// parsed [`Args`] — used by the post-load defence-in-depth path.
pub fn try_early_skip(args: &Args) -> bool {
    if std::env::var_os("WILD_INCREMENTAL_DEBUG").is_none() {
        return false;
    }
    if std::env::var_os("WILD_INCREMENTAL_NO_EARLY_SKIP").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        return false;
    }
    early_skip_impl(args)
}

/// Update the output's mtime so build systems (cargo, make) that
/// look at timestamps see the file as freshly produced by this
/// invocation. Equivalent to `touch -c -a -m <output>`.
///
/// Non-fatal — failure is silently swallowed. If the mtime doesn't
/// update, the next build may see the output as stale and trigger
/// a real relink, which falls through to the cold path. That's a
/// correctness-preserving downgrade (we'd re-link unnecessarily),
/// not a correctness bug.
pub fn bump_output_mtime(args: &Args) {
    bump_output_path_mtime(args.output_path());
}

/// Path-taking variant of [`bump_output_mtime`] — used from the
/// pre-argparse skip where we only have an output path, no parsed
/// `Args`.
pub fn bump_output_path_mtime(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return;
        };
        // SAFETY: `cpath` is a valid nul-terminated C string;
        // `utimensat(…, NULL, 0)` is a POSIX-defined way to set
        // atime+mtime to "now" with no side effects on failure.
        unsafe {
            libc::utimensat(libc::AT_FDCWD, cpath.as_ptr(), std::ptr::null(), 0);
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn early_skip_impl(args: &Args) -> bool {
    let argv: Vec<String> = std::env::args().collect();
    let args_hash = incremental_cache::compute_args_hash(&argv);
    let hashes_path = incremental_cache::hashes_path_for_output(args.output_path());
    let Some(cached) = incremental_cache::read_link_cache(&hashes_path) else {
        eprintln!(
            "wild incremental: early skip: no cache at {}",
            hashes_path.display()
        );
        return false;
    };
    if cached.wild_version != incremental_cache::WILD_VERSION {
        eprintln!(
            "wild incremental: early skip: wild version mismatch (cached {} vs {})",
            cached.wild_version,
            incremental_cache::WILD_VERSION
        );
        return false;
    }
    if cached.args_hash != args_hash {
        eprintln!("wild incremental: early skip: args_hash mismatch");
        return false;
    }
    if incremental_cache::verify_cached_inputs_unchanged(&cached.inputs).is_none() {
        eprintln!("wild incremental: early skip: input fingerprint mismatch");
        return false;
    }
    match std::fs::metadata(args.output_path()) {
        Ok(m) if m.len() == cached.output_size => {
            eprintln!(
                "wild incremental: EARLY SKIP — output at {} reused, \
                 thread pool / linker arenas bypassed",
                args.output_path().display()
            );
            true
        }
        Ok(m) => {
            eprintln!(
                "wild incremental: early skip: output size mismatch ({} vs cached {})",
                m.len(),
                cached.output_size
            );
            false
        }
        Err(e) => {
            eprintln!("wild incremental: early skip: output stat failed: {e}");
            false
        }
    }
}

/// Sets up whatever tracing, if any, is indicated by the supplied arguments. This can only be
/// called once and only if nothing else has already set the global tracing dispatcher. Calling this
/// is optional. If it isn't called, no tracing-based features will function. e.g. --time.
pub fn setup_tracing(args: &Args) -> Result<(), AlreadyInitialised> {
    if let Some(opts) = args.common().time_phase_options.as_ref() {
        timing::init_tracing(opts)
    } else if args.common().print_allocations.is_some() {
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
    #[allow(dyn_drop)]
    /// This is just here so that we defer its destruction. This allows us to (a) measure how long
    /// it takes to drop and (b) if we forked, signal our parent that we're done, then drop it in
    /// the background.
    layout: Option<Box<dyn Drop + 'layout_inputs>>,
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
        args: &'layout_inputs Args,
        // We don't actually use this, but take it as an argument to ensure that the caller has
        // created it. We may decide to actually use it in future, if we stop using rayon's global
        // thread pool.
        _thread_pool: &crate::args::ThreadPool,
    ) -> error::Result<LinkerOutput<'layout_inputs>> {
        let identity = args.common().linker_identity();
        match args.common().version_mode {
            args::VersionMode::ExitAfterPrint => {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{identity}")?;
                return Ok(LinkerOutput { layout: None });
            }
            args::VersionMode::Verbose => {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{identity}")?;
                // Continue linking
            }
            args::VersionMode::None => {
                // Don't print version
            }
        }

        match args {
            Args::Elf(elf_args) => Elf::link_for_arch(self, elf_args),
            Args::MachO(macho_args) => MachO::link_for_arch(self, macho_args),
            Args::Wasm(wasm_args) => wasm::Wasm::link_for_arch(self, wasm_args),
        }
    }

    fn link_for_arch<'data, P: Platform, A: Arch<Platform = P>>(
        &'data self,
        args: &'data P::Args,
    ) -> error::Result<LinkerOutput<'data>> {
        let mut file_loader = input_data::FileLoader::new(&self.inputs_arena);

        // Note, we propagate errors from `link_with_input_data` after we've checked if any files
        // changed. We want inputs-changed errors to take precedence over all other errors.
        let result = self.load_inputs_and_link::<P, A>(&mut file_loader, args);

        file_loader.verify_inputs_unchanged()?;

        // Incremental link — persist the signature + input hashes
        // for the next link. Skipped entirely when the env var is
        // unset; on skip-paths the prior cache is already current,
        // so we only persist on a full-link path.
        if result.is_ok() && std::env::var_os("WILD_INCREMENTAL_DEBUG").is_some() {
            persist_link_cache::<P>(&file_loader, args);
        }

        // Write the dependency file and inputs trace after successful linking.
        if result.is_ok() {
            if let Some(dep_file_path) = &args.dependency_file() {
                write_dependency_file(dep_file_path, args.output(), &file_loader.loaded_files)
                    .with_context(|| {
                        format!(
                            "Failed to write dependency file `{}`",
                            dep_file_path.display()
                        )
                    })?;
            }
            if args.should_write_trace_file() {
                let mut buf = BufWriter::new(std::io::stdout());
                for input in &file_loader.loaded_files {
                    writeln!(buf, "{}", input.filename.display())?;
                }
            }
        }

        result
    }

    fn load_inputs_and_link<'data, P: Platform, A: Arch<Platform = P>>(
        &'data self,
        file_loader: &mut FileLoader<'data>,
        args: &'data P::Args,
    ) -> error::Result<LinkerOutput<'data>> {
        // Incremental *pre-load* skip — fires before `load_inputs`
        // even opens a file. If the cache's args_hash + wild_version
        // + per-input fingerprints + output_size all match what's
        // on disk right now, we can short-circuit with zero mmap,
        // zero archive extraction, zero symbol parsing.
        //
        // Differs from `try_whole_link_skip` (which runs after
        // load_inputs) in WHERE it fires; both produce the same
        // verdict under a valid cache. Keeping the post-load version
        // as defence-in-depth for paths where the pre-load check
        // can't run (first link, cache v-mismatch, explicit
        // WILD_INCREMENTAL_PRE_LOAD_SKIP=0 opt-out).
        if std::env::var_os("WILD_INCREMENTAL_DEBUG").is_some()
            && std::env::var_os("WILD_INCREMENTAL_PRE_LOAD_SKIP").as_deref()
                != Some(std::ffi::OsStr::new("0"))
            && try_pre_load_skip::<P>(args)
        {
            return Ok(LinkerOutput { layout: None });
        }

        let mut plugin = P::maybe_init_linker_plugin(args, &self.linker_plugin_arena, &self.herd)?;

        let loaded = file_loader.load_inputs::<P>(&args.common().inputs, args, &mut plugin);

        args.common().save_dir.finish(file_loader, args)?;

        let loaded = loaded?;

        // Post-load fallback: same signature check, but after inputs
        // are fully resolved. Catches cases where argv-level pre-load
        // couldn't see the real input set (e.g. `-l` dylib lookup
        // that resolved to a different dylib since last link).
        if std::env::var_os("WILD_INCREMENTAL_DEBUG").is_some() {
            if try_whole_link_skip::<P>(file_loader, args) {
                return Ok(LinkerOutput { layout: None });
            }
        }

        let output_kind = OutputKind::new(args, file_loader);

        let mut output = file_writer::Output::new(args, output_kind);

        let mut output_sections =
            OutputSections::with_base_address(P::start_memory_address(output_kind));

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

        resolver
            .resolve_symbols_and_select_archive_entries(&mut symbol_db, &mut per_symbol_flags)?;

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
            P::plugin_all_symbols_read(
                plugin,
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

        let layout_rules = layout_rules_builder.build::<P>();

        let resolved = resolver.resolve_sections_and_canonicalise_undefined(
            &mut symbol_db,
            &mut per_symbol_flags,
            &mut output_sections,
            &layout_rules,
        )?;

        let layout = layout::compute::<P, A>(
            symbol_db,
            per_symbol_flags,
            resolved,
            output_sections,
            &mut output,
        )?;

        P::write_output_file::<A>(&mut output, &layout)?;
        diff::maybe_diff()?;

        // We've finished linking. We consider everything from this point onwards as shutdown.
        let (g1, g2) = timing_guard!("Shutdown");
        self.shutdown_scope.store(vec![Box::new(g1), Box::new(g2)]);

        Ok(LinkerOutput {
            layout: Some(Box::new(layout)),
        })
    }
}

impl Default for Linker {
    fn default() -> Self {
        Self::new()
    }
}

/// Pre-load variant of [`try_whole_link_skip`] — runs before
/// `load_inputs` has opened a single file. Verifies the cache's
/// paths + fingerprints + output size directly against the
/// filesystem, bypassing wild's input-resolution pipeline.
///
/// Trade-offs vs the post-load version:
///   * Wins ~130 ms (skip mmap + archive-member extract + symbol parse) when the cache is clean.
///   * May false-miss if the cache is slightly stale — e.g. user changed a `-L` search path such
///     that argv still hashes the same but the resolved input set would differ. In practice
///     argv-hash equality is a strong signal because cargo's invocation is deterministic; if the
///     argv changed, args_hash catches it.
///
/// Returns `true` on a safe skip. Never returns `true` without
/// output-file size + existence + every cached input present.
fn try_pre_load_skip<P: Platform>(args: &P::Args) -> bool {
    let argv: Vec<String> = std::env::args().collect();
    let args_hash = incremental_cache::compute_args_hash(&argv);
    let hashes_path = incremental_cache::hashes_path_for_output(args.output());
    let Some(cached) = incremental_cache::read_link_cache(&hashes_path) else {
        return false;
    };
    if cached.wild_version != incremental_cache::WILD_VERSION {
        return false;
    }
    if cached.args_hash != args_hash {
        return false;
    }
    // Every cached input path must still be present with a matching
    // fingerprint. This catches content changes AND missing / moved
    // inputs without going through wild's own resolver.
    if incremental_cache::verify_cached_inputs_unchanged(&cached.inputs).is_none() {
        return false;
    }
    // Output still on disk at expected size — defence against
    // manual edits / deletes since last link.
    let output_path = args.output();
    match std::fs::metadata(output_path) {
        Ok(m) if m.len() == cached.output_size => {
            eprintln!(
                "wild incremental: PRE-LOAD SKIP — output at {} reused, \
                 load_inputs bypassed",
                output_path.display()
            );
            true
        }
        Ok(_) | Err(_) => false,
    }
}

/// Returns `true` when the current link's signature (inputs + args +
/// wild version) matches the cached one and the previous output file
/// is still on disk at the expected size — i.e. when the caller is
/// safe to return `Ok(LinkerOutput { layout: None })` without running
/// resolve / layout / write. Returns `false` on any mismatch, missing
/// cache, missing output, or size disagreement.
///
/// Emits a terse stderr line explaining the decision so users running
/// with `WILD_INCREMENTAL_DEBUG=1` can see why a skip did or didn't
/// fire.
fn try_whole_link_skip<P: Platform>(file_loader: &FileLoader<'_>, args: &P::Args) -> bool {
    let inputs: Vec<(&std::path::Path, &[u8])> = file_loader
        .loaded_files
        .iter()
        .map(|f| (f.filename.as_path(), f.data()))
        .collect();
    let current_inputs = incremental_cache::hash_loaded_inputs(inputs);
    let argv: Vec<String> = std::env::args().collect();
    let current_args_hash = incremental_cache::compute_args_hash(&argv);

    let hashes_path = incremental_cache::hashes_path_for_output(args.output());
    let Some(cached) = incremental_cache::read_link_cache(&hashes_path) else {
        eprintln!(
            "wild incremental: no cache at {} — cold link (baseline will be \
             captured afterwards)",
            hashes_path.display()
        );
        return false;
    };

    let verdict =
        incremental_cache::classify_signature(&current_args_hash, &current_inputs, &cached);
    match verdict {
        incremental_cache::SignatureVerdict::FullMatch => {
            // Defence-in-depth: the cache believes the output is
            // intact, but verify against the filesystem before
            // trusting it. User could have deleted / truncated the
            // binary; size mismatch forces a cold link.
            let output_path = args.output();
            let size_ok = match std::fs::metadata(output_path) {
                Ok(m) if m.len() == cached.output_size => true,
                Ok(m) => {
                    eprintln!(
                        "wild incremental: signature matched but output size \
                         differs ({} on disk vs {} cached) — cold link",
                        m.len(),
                        cached.output_size
                    );
                    false
                }
                Err(e) => {
                    eprintln!(
                        "wild incremental: signature matched but output missing \
                         ({}: {}) — cold link",
                        output_path.display(),
                        e
                    );
                    false
                }
            };
            if size_ok {
                eprintln!(
                    "wild incremental: FULL LINK SKIP — output at {} reused",
                    output_path.display()
                );
                return true;
            }
            false
        }
        incremental_cache::SignatureVerdict::Mismatch(why) => {
            eprintln!("wild incremental: link signature mismatch: {:?}", why);
            false
        }
    }
}

/// Persist this link's signature next to the output binary so the
/// next link can check for whole-link-skip eligibility. Called only
/// from the successful-link path; errors are non-fatal (a missing
/// cache just forces the next link to cold-baseline).
///
/// If `file_loader.loaded_files` is empty the current link took the
/// pre-load-skip path — there are no inputs to hash and the previous
/// cache is already correct. Return without rewriting, otherwise we'd
/// overwrite a valid cache with an empty input set and the next skip
/// decision would falsely succeed with zero inputs to check.
fn persist_link_cache<'data, P: Platform>(file_loader: &FileLoader<'data>, args: &P::Args) {
    if file_loader.loaded_files.is_empty() {
        return;
    }
    let inputs: Vec<(&std::path::Path, &[u8])> = file_loader
        .loaded_files
        .iter()
        .map(|f| (f.filename.as_path(), f.data()))
        .collect();
    let current_inputs = incremental_cache::hash_loaded_inputs(inputs);
    let argv: Vec<String> = std::env::args().collect();
    let args_hash = incremental_cache::compute_args_hash(&argv);
    let output_size = std::fs::metadata(args.output())
        .map(|m| m.len())
        .unwrap_or(0);
    let cache = incremental_cache::LinkCache {
        args_hash,
        output_size,
        wild_version: incremental_cache::WILD_VERSION.to_owned(),
        inputs: current_inputs,
    };
    let hashes_path = incremental_cache::hashes_path_for_output(args.output());
    if let Err(e) = incremental_cache::write_link_cache(&hashes_path, &cache) {
        eprintln!(
            "wild incremental: failed to persist cache to {}: {}",
            hashes_path.display(),
            e
        );
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

pub fn should_fork(args: &Args) -> bool {
    args.common().should_fork()
}

pub fn activate_thread_pool(args: &mut Args) -> Result<crate::args::ThreadPool> {
    args.common_mut().activate_thread_pool()
}
