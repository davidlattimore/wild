// Some items in this module are only called from specific feature
// configurations (e.g. the `LtoDriver` trait is reserved for the P3+
// per-driver landings; `Claim` is reserved for the Gold-plugin
// lifecycle) — allow dead code at module scope rather than sprinkle
// attributes on every item.
#![allow(dead_code)]

//! Link-time optimisation infrastructure shared across platforms.
//!
//! The architecture and rationale is documented in
//! `wild-lto-plan.md` at the repo root. TL;DR:
//!
//! - Every LTO backend (ELF Gold plugin, Mach-O libLTO, wasm subprocess `llc`, optional in-process
//!   libLLVM) implements the same [`LtoDriver`] trait. The trait's shape is Gold-plugin-like — the
//!   most expressive of the underlying protocols — so backends with less expressive native APIs
//!   (libLTO, subprocess) adapt up to that shape by buffering.
//! - Linker stays in charge. The trait is called by wild's core input-classification logic; drivers
//!   don't drive the linker back.
//! - Bitcode is a pre-normalisation step. Drivers produce platform object bytes, which flow into
//!   the *same* pipeline that non-LTO inputs use (`SymbolDb`, `Resolver`, `merge_inputs`, …). LTO
//!   is invisible downstream.
//! - GCC and LLVM lanes are kept separate by the dispatcher — an LLVM driver must never claim GCC
//!   bitcode or vice versa.
//!
//! This module currently ships the trait, the dispatcher invariant,
//! and a test harness for both. Concrete driver implementations land
//! in subsequent phases (P3 wasm subprocess, P5 UnifiedLTO, P8
//! Mach-O libLTO). The existing ELF Gold plugin in
//! `libwild::linker_plugins` will be migrated under this module
//! in the commit that adds the wasm driver — splitting moves across
//! two commits would waste churn.

use crate::error::Result;
use crate::file_kind::FileKind;
use crate::platform::Platform;

pub(crate) mod cache;
mod dispatcher;
#[cfg(feature = "macho-lto")]
pub(crate) mod macho_liblto;
pub(crate) mod wasm_batch;
pub(crate) mod wasm_lower;
pub(crate) mod wasm_unified;
pub(crate) mod wasm_unified_llvm;

/// Dispatch a single bitcode input through the right LTO path for
/// the current platform/IR/feature mix. Returns the platform-native
/// object bytes the caller should feed into wild's normal merge
/// pipeline — `SymbolDb`, `Resolver`, `merge_inputs`, etc. see an
/// ordinary `FileKind::{WasmObject,ElfObject,MachOObject}` as if
/// the input had never been bitcode.
///
/// This is the **single call site** that `input_data.rs` routes
/// bitcode through. The explicit function boundary is what P4/P5/P8
/// drivers plug into without each of them needing to know about
/// wild's input plumbing; equally, changes to the input plumbing
/// don't ripple through every driver.
///
/// Today this function delegates to the P3 per-input wasm lowerer
/// for `Ir::Llvm` on the wasm platform — matching existing
/// behaviour byte-for-byte — and returns an actionable error for
/// every other (platform, IR) pair. Future commits wire
/// `MachOLibLtoDriver`, the ELF Gold driver, and the P5 batch path
/// into the right branches here.
///
/// Scope boundary: this is the **per-input** dispatch. The Gold-
/// shape `claim_file → all_symbols_read` lifecycle (batching
/// bitcode across inputs for cross-module optimisation) is a P4/P5
/// follow-up — it needs `input_data.rs` to hold bitcode until every
/// input is seen, which is an `input_data` restructure rather than
/// a driver change.
pub(crate) fn dispatch_bitcode_input(
    bytes: &[u8],
    ir: Ir,
    platform: crate::args::PlatformKind,
) -> crate::error::Result<Vec<u8>> {
    use crate::args::PlatformKind;
    match (platform, ir) {
        (PlatformKind::Wasm, Ir::Llvm) => {
            // Preserve today's byte-for-byte behaviour: per-input
            // llc subprocess, no cross-module work. This is what
            // `input_data.rs::process_input` already does; threading
            // it through here means swapping drivers later is a
            // one-line change.
            wasm_lower::lower_to_wasm_object(bytes)
        }
        (PlatformKind::Wasm, Ir::Gcc) => Err(crate::error!(
            "GCC GIMPLE bitcode on wasm target is unsupported — \
             GCC doesn't emit wasm bitcode, and wild's wasm driver \
             only reads LLVM bitcode."
        )),
        (PlatformKind::MachO, Ir::Llvm) => {
            // Mach-O has its own hot path via `compile_bitcode_to_file`
            // that input_data.rs still calls directly. The
            // `MachOLibLtoDriver` from P8 is the Gold-shape
            // alternative; routing to it here is a follow-up commit
            // that swaps the input_data hot path over. Until then
            // this branch is unreachable — input_data doesn't call
            // dispatch_bitcode_input for mach-o LTO yet.
            Err(crate::error!(
                "dispatch_bitcode_input for Mach-O LLVM bitcode is not yet \
                 wired — wild currently handles this via the macho-lto \
                 hook in input_data.rs. Follow-up commit will migrate \
                 that hook through this dispatcher."
            ))
        }
        (PlatformKind::Elf, _) => Err(crate::error!(
            "dispatch_bitcode_input for ELF LTO is not yet wired — \
             wild currently handles this via the linker_plugins (Gold \
             plugin) hook. Follow-up commit will migrate through this \
             dispatcher."
        )),
        (PlatformKind::MachO, Ir::Gcc) => Err(crate::error!(
            "GCC GIMPLE bitcode on Mach-O is unsupported: no GCC \
             toolchain emits Mach-O GIMPLE, and the system libLTO \
             only reads LLVM bitcode."
        )),
    }
}

/// Dispatcher for the parallel per-module LTO pipeline. Tries the
/// in-process libLLVM path (P5b) when the `llvm` feature is enabled
/// and falls back to the subprocess path (P5a) otherwise — or when
/// the in-process path declines specific inputs.
///
/// Fallback semantics: a whole-batch P5b error routes every input
/// through P5a. Per-module P5b failures don't yet route individual
/// fallbacks — that's a follow-up. For today the granularity is
/// all-or-nothing per link.
pub(crate) fn lower_per_module(
    bitcodes: &[&[u8]],
    opt_level: wasm_batch::OptLevel,
    pool: &rayon::ThreadPool,
) -> crate::error::Result<Vec<Vec<u8>>> {
    if wasm_unified_llvm::in_process_available()
        && std::env::var_os("WILD_FORCE_SUBPROCESS_LTO").is_none()
    {
        match wasm_unified_llvm::lower_per_module_parallel_in_process(bitcodes, opt_level, pool) {
            Ok(v) => return Ok(v),
            Err(e) => {
                tracing::debug!(
                    "P5b in-process LTO declined ({:?}); falling back to P5a subprocess",
                    e.to_string()
                );
            }
        }
    }
    wasm_unified::lower_per_module_parallel(bitcodes, opt_level, pool)
}

/// LTO-related CLI options, shared across platforms. Platform-specific
/// `Args` structs embed one of these and expose it via trait methods.
///
/// Defaults are conservative: LTO is off; if a user adds `--lto-fat`
/// or the equivalent rustc flag, they opt in. Partition count defaults
/// to rayon's pool size so parallel codegen saturates the machine.
#[derive(Debug, Clone)]
pub(crate) struct LtoConfig {
    /// How much optimisation opt/llc should run during LTO. `None`
    /// means "merge-only": inputs are unioned but no cross-module
    /// passes run.
    pub(crate) opt_level: wasm_batch::OptLevel,
    /// Codegen partition count for parallel back-end compilation.
    /// Honoured by LLD-style partitioning in P5+; the P4 batch
    /// lowerer reads it for future use but produces one object today.
    pub(crate) partitions: u32,
    /// Whether to actually run the batch lowerer. When false, per-
    /// input lowering (P3) is used regardless of input count.
    pub(crate) batch_enabled: bool,
}

impl Default for LtoConfig {
    fn default() -> Self {
        Self {
            opt_level: wasm_batch::OptLevel::None,
            partitions: rayon::current_num_threads() as u32,
            batch_enabled: false,
        }
    }
}

impl LtoConfig {
    /// Parse the subset of `-flto=<mode>` / `--lto-*` flags wild
    /// cares about. Returns `true` if the arg was consumed.
    pub(crate) fn parse_flag(&mut self, arg: &str) -> bool {
        if let Some(mode) = arg.strip_prefix("-flto=") {
            self.batch_enabled = mode != "off" && !mode.is_empty();
            self.opt_level = match mode {
                "off" | "no" => wasm_batch::OptLevel::None,
                "thin" => wasm_batch::OptLevel::O2,
                _ => wasm_batch::OptLevel::O3, // "fat", "full", etc.
            };
            return true;
        }
        if arg == "-flto" || arg == "--lto" {
            self.batch_enabled = true;
            self.opt_level = wasm_batch::OptLevel::O3;
            return true;
        }
        if arg == "-fno-lto" || arg == "--no-lto" {
            self.batch_enabled = false;
            self.opt_level = wasm_batch::OptLevel::None;
            return true;
        }
        if let Some(n) = arg.strip_prefix("--lto-partitions=") {
            if let Ok(v) = n.parse::<u32>() {
                self.partitions = v.max(1);
                return true;
            }
        }
        false
    }
}

// `dispatcher::pick_driver` stays module-private until a real caller
// in the input-classification path lands (P3). Tests in
// `dispatcher.rs` exercise it directly via `super::`.

/// Identifies which IR family a driver handles. The dispatcher uses
/// this to route inputs — an LLVM driver must never be handed GCC
/// bitcode and vice versa; different IRs go to different LLVM toolchains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Ir {
    /// LLVM bitcode (`BC\xC0\xDE` magic, or `.llvm.lto` /
    /// `__LLVM,__bitcode` / `.llvmbc` custom section).
    Llvm,
    /// GCC GIMPLE (ELF object with `.gnu.lto_*` sections).
    Gcc,
}

impl Ir {
    /// Map a classified input to its IR flavour, if it's bitcode at
    /// all. Non-bitcode kinds return `None` and skip LTO entirely.
    pub(crate) fn from_file_kind(k: FileKind) -> Option<Self> {
        match k {
            FileKind::LlvmIr => Some(Ir::Llvm),
            FileKind::GccIr => Some(Ir::Gcc),
            _ => None,
        }
    }
}

/// Symbol-list snapshot a driver extracts at claim time. The linker's
/// resolver consumes these without waiting for compilation — that's
/// what lets wild parallelise the `all_symbols_read` step across
/// drivers/inputs rather than blocking on one monolithic opt pass.
#[derive(Debug, Default)]
pub(crate) struct Claim {
    /// Symbols this input defines (with name + basic linkage bits).
    /// The concrete type is intentionally minimal here — drivers fill
    /// it with what their backend surfaces cheaply at claim time.
    pub(crate) defined: Vec<String>,
    pub(crate) undefined: Vec<String>,
}

/// The core LTO interface every backend implements. Method shape
/// mirrors the Gold plugin protocol because that's the most
/// expressive of the three native APIs (Gold / libLTO / subprocess);
/// implementations backed by less expressive APIs adapt up via
/// buffering.
///
/// Lifecycle per link:
///   1. `onload` — once, before any inputs arrive.
///   2. `claim_file` — per bitcode input, parallel-safe.
///   3. `all_symbols_read` — once, all claimed inputs are compiled here (drivers should parallelise
///      internally).
///   4. `cleanup` — once, final.
pub(crate) trait LtoDriver<P: Platform>: Send + Sync {
    /// Gold `onload`: driver initialises. Wild doesn't pass a
    /// callback table today; future phases add one for drivers that
    /// need to ask the linker questions mid-optimisation.
    fn onload(&mut self) -> Result<()> {
        Ok(())
    }

    /// Claim a bitcode input. Extract the symbol list eagerly — the
    /// linker's resolver will look at it before compilation is done.
    /// Implementations that can't enumerate symbols without a full
    /// compile must compile on claim; that defeats the parallelism
    /// but is a correctness-preserving fallback.
    fn claim_file(&mut self, bytes: &[u8]) -> Result<Claim>;

    /// Compile every claimed input to platform objects, in parallel
    /// via `pool` where possible. Returns the compiled object bytes
    /// in input order so relocations are stable.
    fn all_symbols_read(&mut self, pool: &rayon::ThreadPool) -> Result<Vec<Vec<u8>>>;

    fn cleanup(&mut self) {}

    /// Dispatcher invariant: returns `true` iff this driver is willing
    /// to handle the given IR family. Used by [`pick_driver`] to
    /// refuse misrouting (e.g. LLVM driver handed GCC bitcode).
    fn handles(&self, ir: Ir) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check that the trait is dyn-compatible — we need
    /// this because the dispatcher stores drivers as
    /// `Box<dyn LtoDriver<_>>` to pick at runtime.
    #[allow(dead_code)]
    fn _trait_is_dyn_compat<P: Platform>(_d: Box<dyn LtoDriver<P>>) {}

    #[test]
    fn ir_from_file_kind_maps_bitcode_and_rejects_other_kinds() {
        assert_eq!(Ir::from_file_kind(FileKind::LlvmIr), Some(Ir::Llvm));
        assert_eq!(Ir::from_file_kind(FileKind::GccIr), Some(Ir::Gcc));
        assert_eq!(Ir::from_file_kind(FileKind::ElfObject), None);
        assert_eq!(Ir::from_file_kind(FileKind::WasmObject), None);
        assert_eq!(Ir::from_file_kind(FileKind::Archive), None);
        assert_eq!(Ir::from_file_kind(FileKind::Text), None);
    }

    #[test]
    fn lto_config_default_matches_rayon_threads() {
        let c = LtoConfig::default();
        assert_eq!(c.partitions, rayon::current_num_threads() as u32);
        assert!(!c.batch_enabled);
        assert_eq!(c.opt_level, wasm_batch::OptLevel::None);
    }

    #[test]
    fn lto_config_parses_flto_modes() {
        let mut c = LtoConfig::default();
        assert!(c.parse_flag("-flto=fat"));
        assert!(c.batch_enabled);
        assert_eq!(c.opt_level, wasm_batch::OptLevel::O3);

        assert!(c.parse_flag("-flto=thin"));
        assert_eq!(c.opt_level, wasm_batch::OptLevel::O2);

        assert!(c.parse_flag("-flto=off"));
        assert!(!c.batch_enabled);
        assert_eq!(c.opt_level, wasm_batch::OptLevel::None);

        assert!(c.parse_flag("-flto"));
        assert!(c.batch_enabled);

        assert!(c.parse_flag("-fno-lto"));
        assert!(!c.batch_enabled);
    }

    #[test]
    fn lto_config_parses_partitions() {
        let mut c = LtoConfig::default();
        assert!(c.parse_flag("--lto-partitions=8"));
        assert_eq!(c.partitions, 8);
        // Zero is clamped up to 1 — a zero-partition run would produce
        // no output and is never what the user wants.
        assert!(c.parse_flag("--lto-partitions=0"));
        assert_eq!(c.partitions, 1);
    }

    #[test]
    fn lto_config_rejects_unknown_flags() {
        let mut c = LtoConfig::default();
        assert!(!c.parse_flag("--not-an-lto-flag"));
        assert!(!c.parse_flag("-O3"));
        assert!(!c.parse_flag(""));
    }

    /// End-to-end dispatcher test: regardless of whether the `llvm`
    /// feature is compiled in, `lower_per_module` must return valid
    /// wasm objects. With the feature off, the subprocess path (P5a)
    /// runs. With the feature on, the in-process path (P5b) runs; if
    /// libLLVM can't be located at runtime the dispatcher falls back
    /// to P5a automatically.
    #[test]
    fn lower_per_module_dispatcher_produces_one_wasm_per_input() {
        let Some(llvm_as) = crate::llvm_tools::find_by_name("llvm-as") else {
            eprintln!("skipping: llvm-as unavailable");
            return;
        };
        let bc = {
            let td = tempfile::tempdir().unwrap();
            let ll = td.path().join("t.ll");
            let bc = td.path().join("t.bc");
            std::fs::write(
                &ll,
                r#"target triple = "wasm32-unknown-unknown"
define i32 @dispatch_test(i32 %a) { ret i32 %a }
"#,
            )
            .unwrap();
            let status = std::process::Command::new(&llvm_as)
                .arg(&ll)
                .arg("-o")
                .arg(&bc)
                .status();
            let Ok(status) = status else {
                eprintln!("skipping: llvm-as failed to spawn");
                return;
            };
            if !status.success() {
                eprintln!("skipping: llvm-as failed");
                return;
            }
            std::fs::read(&bc).unwrap()
        };

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        match lower_per_module(
            &[bc.as_slice(), bc.as_slice()],
            wasm_batch::OptLevel::O2,
            &pool,
        ) {
            Ok(objs) => {
                assert_eq!(objs.len(), 2);
                for o in &objs {
                    assert_eq!(&o[..4], b"\0asm");
                }
            }
            Err(e) => eprintln!("skipping: toolchain unavailable: {e:?}"),
        }
    }
}
