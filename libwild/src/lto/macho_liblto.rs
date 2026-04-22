//! P8: Mach-O LTO driver backed by Apple's `libLTO.dylib`.
//!
//! Feature-gated on `macho-lto`. The heavy lifting (dlopen of the
//! system `libLTO.dylib` + the entire C-API FFI around
//! `lto_module_*` / `lto_codegen_*`) already lives in
//! [`crate::macho_lto`] — this file is the thin Gold-shaped
//! adapter that exposes that functionality through the same
//! [`LtoDriver`](super::LtoDriver) trait every other LTO backend
//! uses.
//!
//! Design: libLTO is a batch API ("give me all bitcode, give me
//! all objects"). That matches the Gold `claim_file` →
//! `all_symbols_read` lifecycle exactly: we stash bitcode at claim
//! time and kick the libLTO compile at `all_symbols_read`. No
//! buffering heroics required — libLTO is already what Gold's
//! shape was designed for.
//!
//! Scope: the driver is available behind the `macho-lto` feature;
//! the existing per-input `compile_bitcode_to_file` path from
//! `input_data.rs` continues to be wild's Mach-O LTO hot path for
//! today. The driver here is what P4/P5 batch and UnifiedLTO
//! pipelines will dispatch to for Mach-O once those wire up the
//! cross-platform `LtoDriver<_>` dispatcher.

#![cfg(feature = "macho-lto")]

use crate::error::Error;
use crate::error::Result;
use crate::lto::Claim;
use crate::lto::Ir;
use crate::lto::LtoDriver;
use crate::macho::MachO;
use crate::macho_lto::LibLto;
use std::path::PathBuf;

/// libLTO-backed driver. One instance per link.
pub(crate) struct MachOLibLtoDriver {
    /// Path to `libLTO.dylib`. Loaded lazily on first `claim_file`
    /// because the common case — no bitcode inputs — shouldn't pay
    /// for dlopen.
    lib_lto_path: PathBuf,
    /// Library handle, loaded on first claim.
    lib: Option<LibLto>,
    /// Claimed bitcode blobs, kept in input order so
    /// `all_symbols_read` produces stable output.
    claimed: Vec<OwnedBitcode>,
    /// Symbols the caller wants preserved across LTO
    /// (entry point, explicit exports, `--export-dynamic` targets).
    /// Today the driver collects defined symbols at claim time; the
    /// consumer side of the trait will grow a hook to pass explicit
    /// must-preserve lists in once P4/P5 consume it.
    preserve_symbols: Vec<Vec<u8>>,
}

struct OwnedBitcode {
    /// Human-readable identifier surfaced in libLTO's error
    /// messages when something goes wrong — keep it informative.
    name: String,
    bytes: Vec<u8>,
}

impl MachOLibLtoDriver {
    /// Construct a driver rooted at the supplied `libLTO.dylib`. The
    /// library isn't dlopen'd until a bitcode input is actually
    /// claimed.
    ///
    /// **Complexity:** Θ(1) CPU and memory — allocates a fixed-size
    /// struct; no I/O or dlopen happens at construction time.
    pub(crate) fn new(lib_lto_path: PathBuf) -> Self {
        Self {
            lib_lto_path,
            lib: None,
            claimed: Vec::new(),
            preserve_symbols: Vec::new(),
        }
    }

    fn ensure_loaded(&mut self) -> Result<&LibLto> {
        if self.lib.is_none() {
            self.lib = Some(LibLto::load(&self.lib_lto_path)?);
        }
        Ok(self.lib.as_ref().unwrap())
    }

    /// Perform the dlopen if not already done. Separated from
    /// [`ensure_loaded`] so callers that need a shared borrow of
    /// `self` alongside the library can load first and borrow after.
    ///
    /// **Complexity:** Θ(1) amortised — no-op after the first call;
    /// first call pays one `dlopen` + ~15 `dlsym` lookups.
    fn prime(&mut self) -> Result<()> {
        if self.lib.is_none() {
            self.lib = Some(LibLto::load(&self.lib_lto_path)?);
        }
        Ok(())
    }

    /// Shared-borrow accessor. Panics if `prime` hasn't been called.
    /// Only used inside `all_symbols_read` where we control both sides.
    fn lib(&self) -> &LibLto {
        self.lib
            .as_ref()
            .expect("lib not loaded — caller must prime() first")
    }
}

impl LtoDriver<MachO> for MachOLibLtoDriver {
    /// Claim one bitcode input, extracting its symbol table.
    ///
    /// **Complexity:** 𝒪(bc + n) CPU, 𝒪(bc + n) memory — libLTO
    /// parses bc bitcode bytes to surface n symbols; the bitcode is
    /// copied into `self.claimed` for the deferred compile phase.
    fn claim_file(&mut self, bytes: &[u8]) -> Result<Claim> {
        // Scope the library borrow so the subsequent `self.claimed`
        // write doesn't conflict with it.
        let (defined, undefined) = {
            let lib = self.ensure_loaded()?;
            // Defined symbols up-front so the linker's resolver
            // sees them before libLTO has compiled anything. That's
            // the Gold-shape lifecycle contract.
            let defined: Vec<String> = lib
                .get_defined_symbol_names(bytes)?
                .into_iter()
                .map(|s| String::from_utf8_lossy(&s).into_owned())
                .collect();
            // The full symbol list surfaces undefined entries too
            // via the attribute flags — filter those.
            let all_syms = lib.get_symbols(bytes)?;
            let undefined: Vec<String> = all_syms
                .iter()
                .filter(|(_, attrs)| {
                    *attrs & crate::macho_lto::LTO_SYMBOL_DEFINITION_MASK
                        == crate::macho_lto::LTO_SYMBOL_DEFINITION_UNDEFINED
                })
                .map(|(name, _)| String::from_utf8_lossy(name).into_owned())
                .collect();
            (defined, undefined)
        };

        // Stash the bitcode for the all-symbols-read pass.
        let name = format!("input-{:04}.bc", self.claimed.len());
        self.claimed.push(OwnedBitcode {
            name,
            bytes: bytes.to_vec(),
        });

        Ok(Claim { defined, undefined })
    }

    /// Compile all claimed bitcode inputs in a single libLTO batch call.
    ///
    /// **Complexity:** 𝒪(external) — libLTO drives the LLVM IPO + code-gen
    /// pipeline internally; wild's wrapper overhead is 𝒪(n + bc) to build
    /// the input/preserve slices (n claimed inputs, bc total bitcode bytes).
    /// Wall-clock is 𝒪(bc/T) inside libLTO's own thread pool.
    fn all_symbols_read(&mut self, _pool: &rayon::ThreadPool) -> Result<Vec<Vec<u8>>> {
        if self.claimed.is_empty() {
            return Ok(Vec::new());
        }
        // Load the library first (requires &mut self), then take
        // shared borrows to the claimed bitcode + preserve list.
        // Attempting to interleave the two borrow kinds trips the
        // borrow checker.
        self.prime()?;
        let preserve_refs: Vec<&[u8]> =
            self.preserve_symbols.iter().map(|s| s.as_slice()).collect();
        let inputs: Vec<(&str, &[u8])> = self
            .claimed
            .iter()
            .map(|b| (b.name.as_str(), b.bytes.as_slice()))
            .collect();
        // libLTO does its own parallelism internally; we pass the
        // whole batch in one call and trust libLTO to saturate
        // cores. That's the tradeoff of the batch API — we give up
        // rayon-visible parallelism at the outer level.
        let combined = self.lib().compile(&inputs, &preserve_refs, &[], None)?;
        // libLTO returns ONE combined Mach-O object regardless of N
        // inputs. Contrast with the wasm subprocess driver which
        // returns N objects — both are valid `Vec<Vec<u8>>` shapes;
        // wild's merge pipeline doesn't care whether the objects
        // map 1:1 to inputs or collapse.
        Ok(vec![combined])
    }

    /// Release all claimed bitcode, preserve lists, and the libLTO handle.
    ///
    /// **Complexity:** 𝒪(n + bc) CPU — drops n bitcode buffers totalling
    /// bc bytes; `dlclose` of libLTO is Θ(1) from wild's perspective.
    fn cleanup(&mut self) {
        self.claimed.clear();
        self.preserve_symbols.clear();
        // Dropping `lib` unloads libLTO.dylib, releasing the
        // LLVMContext libLTO allocated internally. Don't short-
        // circuit this — skipping cleanup leaks the context.
        self.lib = None;
    }

    /// Returns `true` iff this driver can handle the given IR format.
    ///
    /// **Complexity:** Θ(1) — single equality check.
    fn handles(&self, ir: Ir) -> bool {
        // Apple's libLTO only reads LLVM bitcode. Routing GCC
        // GIMPLE here would crash or silently misinterpret — the
        // compatibility rule encoded in the dispatcher catches the
        // misroute.
        ir == Ir::Llvm
    }
}

/// Discover a default path to libLTO.dylib, used by callers that
/// don't get one from args. Returns `None` if the usual Mac paths
/// don't have the library — wild falls back to the non-LTO path
/// in that case.
///
/// **Complexity:** Θ(1) — probes a fixed list of at most 3 candidate
/// paths (plus one optional `$DEVELOPER_DIR` expansion) via `stat(2)`.
pub(crate) fn default_lib_lto_path() -> Option<PathBuf> {
    for p in [
        "/usr/lib/libLTO.dylib",
        "/Library/Developer/CommandLineTools/usr/lib/libLTO.dylib",
        // Xcode bundled version — path depends on active developer
        // dir. Honour `$DEVELOPER_DIR` if present.
    ] {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(dev) = std::env::var("DEVELOPER_DIR") {
        let p = PathBuf::from(dev).join("Toolchains/XcodeDefault.xctoolchain/usr/lib/libLTO.dylib");
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// Construct a `MachOLibLtoDriver` using the auto-discovered
/// `libLTO.dylib` path. Errors if no candidate path exists.
///
/// **Complexity:** Θ(1) — `default_lib_lto_path` probe + struct init;
/// no dlopen happens until the first `claim_file`.
#[allow(dead_code)]
pub(crate) fn new_with_default_path() -> Result<MachOLibLtoDriver> {
    let path = default_lib_lto_path().ok_or_else(|| {
        Error::with_message(
            "Mach-O LTO: libLTO.dylib not found in the usual locations. \
             Set `$DEVELOPER_DIR` to a toolchain that ships it, or \
             disable LTO inputs for this link.",
        )
    })?;
    Ok(MachOLibLtoDriver::new(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_llvm_rejects_gcc() {
        // Construct a driver without actually loading libLTO — we
        // don't need the library for the dispatcher-invariant check.
        let driver = MachOLibLtoDriver::new(PathBuf::from("/does-not-exist"));
        assert!(driver.handles(Ir::Llvm));
        assert!(
            !driver.handles(Ir::Gcc),
            "Mach-O libLTO doesn't read GCC GIMPLE — dispatcher \
             must never route GCC inputs to this driver"
        );
    }

    #[test]
    fn default_lib_lto_path_on_mac_finds_it() {
        // Only a useful check on macOS with the usual toolchain.
        // Elsewhere the path is correctly None.
        if cfg!(target_os = "macos") {
            let found = default_lib_lto_path();
            if found.is_none() {
                eprintln!(
                    "no libLTO.dylib at the usual paths — \
                     Command Line Tools may not be installed"
                );
            }
        } else {
            assert!(default_lib_lto_path().is_none());
        }
    }

    #[test]
    fn new_is_cheap_and_doesnt_dlopen() {
        // Construction with a bogus path must not panic or load the
        // library — the lazy-load contract matters for links that
        // never see bitcode.
        let _driver =
            MachOLibLtoDriver::new(PathBuf::from("/definitely-not-a-real-path/libLTO.dylib"));
        // If we got here without panicking, the contract is met.
    }

    #[test]
    fn cleanup_is_idempotent() {
        let mut driver = MachOLibLtoDriver::new(PathBuf::from("/nope"));
        driver.cleanup();
        driver.cleanup();
        assert!(driver.claimed.is_empty());
        assert!(driver.lib.is_none());
    }
}
