//! Picks the right `LtoDriver` for an IR flavour on a given platform.
//!
//! The invariant enforced here is the compatibility rule from
//! `wild-lto-plan.md`:
//!
//! > wild must link any project it links today, regardless of which
//! > optional features are compiled in.
//!
//! Specifically:
//! - GCC bitcode MUST only route to a driver that advertises [`Ir::Gcc`] via
//!   [`LtoDriver::handles`]. An LLVM driver seeing GIMPLE would produce silent corruption.
//! - LLVM bitcode MUST only route to a driver advertising [`Ir::Llvm`]. A GCC driver has no
//!   understanding of LLVM's bitcode layout.
//! - If no driver claims an IR, the caller surfaces a rustc-style diagnostic (see
//!   `symbol_db::linker_plugin_disabled_error`).

use super::Ir;
use super::LtoDriver;
use crate::platform::Platform;

/// Pick the first registered driver willing to handle `ir` for
/// platform `P`. Returns `None` if none advertised it — the caller
/// must surface a diagnostic (we don't here because the caller has
/// context about which file triggered the routing).
///
/// The ordering of `drivers` is the dispatch preference: callers
/// register faster/preferred drivers first (e.g. in-process
/// libLLVM before subprocess-llc).
pub(crate) fn pick_driver<'a, P: Platform>(
    drivers: &'a mut [Box<dyn LtoDriver<P>>],
    ir: Ir,
) -> Option<&'a mut dyn LtoDriver<P>> {
    for d in drivers.iter_mut() {
        if d.handles(ir) {
            debug_assert!(
                d.handles(ir),
                "dispatcher invariant: chosen driver must handle the requested IR"
            );
            return Some(d.as_mut());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result;
    use crate::lto::Claim;

    /// Minimal fake driver for routing tests. Records what it was
    /// asked, so we can assert on misroutings.
    struct Fake {
        accepts: &'static [Ir],
        claims_made: std::cell::Cell<u32>,
    }

    // SAFETY: the Cell is only touched behind `&mut self` methods
    // in these tests; Sync is needed for the trait bound only.
    unsafe impl Sync for Fake {}

    impl<P: Platform> LtoDriver<P> for Fake {
        fn claim_file(&mut self, _bytes: &[u8]) -> Result<Claim> {
            self.claims_made.set(self.claims_made.get() + 1);
            Ok(Claim::default())
        }
        fn all_symbols_read(&mut self, _pool: &rayon::ThreadPool) -> Result<Vec<Vec<u8>>> {
            Ok(Vec::new())
        }
        fn handles(&self, ir: Ir) -> bool {
            self.accepts.contains(&ir)
        }
    }

    fn mk(accepts: &'static [Ir]) -> Box<dyn LtoDriver<crate::elf::Elf>> {
        Box::new(Fake {
            accepts,
            claims_made: std::cell::Cell::new(0),
        })
    }

    #[test]
    fn picks_first_matching_driver() {
        let mut drivers: Vec<Box<dyn LtoDriver<crate::elf::Elf>>> =
            vec![mk(&[Ir::Llvm]), mk(&[Ir::Gcc]), mk(&[Ir::Llvm, Ir::Gcc])];
        assert!(pick_driver(&mut drivers, Ir::Llvm).is_some());
        assert!(pick_driver(&mut drivers, Ir::Gcc).is_some());
    }

    #[test]
    fn returns_none_when_no_driver_handles_ir() {
        let mut drivers: Vec<Box<dyn LtoDriver<crate::elf::Elf>>> = vec![mk(&[Ir::Llvm])];
        assert!(pick_driver(&mut drivers, Ir::Gcc).is_none());
    }

    #[test]
    fn dispatcher_respects_registration_order() {
        // First LLVM driver wins even though a second one also handles it.
        let mut drivers: Vec<Box<dyn LtoDriver<crate::elf::Elf>>> =
            vec![mk(&[Ir::Llvm]), mk(&[Ir::Llvm])];
        let chosen = pick_driver(&mut drivers, Ir::Llvm).unwrap();
        // `claim_file` fires only the first driver; the second keeps 0 claims.
        chosen.claim_file(&[]).unwrap();
        let a: &Fake = unsafe {
            // SAFETY: single-threaded test; we know the trait-object
            // erases to `Fake`. This is test-only; production code
            // never downcasts.
            &*(drivers[0].as_ref() as *const dyn LtoDriver<crate::elf::Elf> as *const Fake)
        };
        let b: &Fake = unsafe {
            &*(drivers[1].as_ref() as *const dyn LtoDriver<crate::elf::Elf> as *const Fake)
        };
        assert_eq!(a.claims_made.get(), 1);
        assert_eq!(b.claims_made.get(), 0);
    }

    #[test]
    fn gcc_bitcode_never_routes_to_llvm_only_driver() {
        // The property the compatibility rule protects:
        // an LLVM-only driver cannot be picked for GCC input.
        let mut drivers: Vec<Box<dyn LtoDriver<crate::elf::Elf>>> = vec![mk(&[Ir::Llvm])];
        assert!(
            pick_driver(&mut drivers, Ir::Gcc).is_none(),
            "an LLVM-only driver must not claim GCC bitcode"
        );
    }
}
