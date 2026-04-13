//! `LinkerHints` — opt-in metadata interface.
//!
//! When wilt is invoked from a wasm linker (e.g. `wild`'s wasm front-end),
//! the linker has knowledge that's lost in a finalised `.wasm` file:
//! the closed-world set of callers, function reachability via ref.func
//! and tables, original input-object identity, and so on. Standalone wilt
//! has to assume the open world.
//!
//! Passes that consume hints check `Option<&dyn LinkerHints>` and fall
//! back to today's conservative inference when `None`. Methods all have
//! default impls returning the conservative answer, so every method is
//! safe to ignore.
//!
//! This is just the surface (Plan C, milestone M1). No pass consumes
//! hints yet — `dae_v2` (M2) is the first.

/// Concrete constant value sitting in an immutable global, returned
/// from `LinkerHints::global_const`. Encodings match the wasm binary
/// immediate exactly (signed LEB for ints, raw little-endian bytes for
/// floats) so callers can splice them in without re-encoding semantics.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConstVal {
    I32(i32),
    I64(i64),
    F32(u32),
    F64(u64),
}

pub trait LinkerHints: Sync {
    /// Function is unreachable from outside the module — never exported,
    /// never reachable via ref.func or table init. Default: conservatively
    /// assume the function is reachable from outside.
    fn is_internal(&self, _func_idx: u32) -> bool { false }

    /// Number of static call sites for this function across the link set.
    /// `Some(1)` enables aggressive single-call-site inlining. Default:
    /// unknown.
    fn call_count(&self, _func_idx: u32) -> Option<u32> { None }

    /// Functions reachable through this table. Closes the `call_indirect`
    /// target set. Default: unknown (caller must assume any function is
    /// reachable).
    fn table_targets(&self, _table_idx: u32) -> Option<&[u32]> { None }

    /// Every function index that appears as a `ref.func` anywhere in the
    /// link set (bodies, element segments, global init exprs).
    /// Default: empty — combined with `is_internal == false` this means
    /// "assume nothing".
    fn ref_func_targets(&self) -> &[u32] { &[] }

    /// Original input-object index, for layout / locality passes that
    /// want to cluster bodies that came from the same TU.
    fn origin_unit(&self, _func_idx: u32) -> Option<u32> { None }

    /// True if this global is read anywhere in the link set. Default:
    /// conservatively assume it is.
    fn global_is_read(&self, _global_idx: u32) -> bool { true }

    /// If this global is non-mutable and its init expression is a
    /// single constant (i32.const / i64.const / f32.const / f64.const),
    /// the literal value. Anything else — mutable, ref.func init,
    /// imported global that can only be known at link time — returns
    /// `None`. Default: unknown.
    fn global_const(&self, _global_idx: u32) -> Option<ConstVal> { None }

    /// True if the function has no observable side effects: no stores,
    /// no global.set, no table writes, no memory.grow / memory.copy /
    /// memory.init / memory.fill, no call_indirect, and every direct
    /// callee is also pure. Imports are conservatively impure.
    /// Default: assume impure.
    fn func_is_pure(&self, _func_idx: u32) -> bool { false }
}

/// No-op hints — equivalent to passing `None`. Useful when an API needs
/// a `&dyn LinkerHints` regardless.
pub struct NoHints;
impl LinkerHints for NoHints {}

pub mod derived;
pub use derived::DerivedHints;

/// Test fixtures for `LinkerHints`. Cheap and pure; always exposed so
/// downstream integration tests (and wild itself) can use it without a
/// feature flag.
pub mod testing {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// Hardcoded hints for tests. Empty `FixedHints::default()` is
    /// equivalent to `NoHints`.
    #[derive(Default)]
    pub struct FixedHints {
        pub internal: HashSet<u32>,
        pub call_counts: HashMap<u32, u32>,
        pub tables: HashMap<u32, Vec<u32>>,
        pub ref_funcs: Vec<u32>,
        pub origins: HashMap<u32, u32>,
        pub unread_globals: HashSet<u32>,
        pub global_consts: HashMap<u32, ConstVal>,
        pub pure_funcs: HashSet<u32>,
    }

    impl LinkerHints for FixedHints {
        fn is_internal(&self, f: u32) -> bool { self.internal.contains(&f) }
        fn call_count(&self, f: u32) -> Option<u32> { self.call_counts.get(&f).copied() }
        fn table_targets(&self, t: u32) -> Option<&[u32]> {
            self.tables.get(&t).map(|v| v.as_slice())
        }
        fn ref_func_targets(&self) -> &[u32] { &self.ref_funcs }
        fn origin_unit(&self, f: u32) -> Option<u32> { self.origins.get(&f).copied() }
        fn global_is_read(&self, g: u32) -> bool { !self.unread_globals.contains(&g) }
        fn global_const(&self, g: u32) -> Option<ConstVal> { self.global_consts.get(&g).copied() }
        fn func_is_pure(&self, f: u32) -> bool { self.pure_funcs.contains(&f) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::FixedHints;

    #[test]
    fn defaults_are_conservative() {
        let n = NoHints;
        assert!(!n.is_internal(0));         // assume external
        assert_eq!(n.call_count(0), None);  // unknown
        assert!(n.table_targets(0).is_none());
        assert!(n.ref_func_targets().is_empty());
        assert_eq!(n.origin_unit(0), None);
        assert!(n.global_is_read(0));        // assume read
        assert_eq!(n.global_const(0), None);
        assert!(!n.func_is_pure(0));
    }

    #[test]
    fn fixed_hints_round_trip() {
        let mut h = FixedHints::default();
        h.internal.insert(0);
        h.internal.insert(7);
        h.call_counts.insert(0, 1);
        h.tables.insert(0, vec![3, 5]);
        h.ref_funcs = vec![5];
        h.origins.insert(0, 42);
        h.unread_globals.insert(2);

        assert!(h.is_internal(0));
        assert!(!h.is_internal(1));
        assert_eq!(h.call_count(0), Some(1));
        assert_eq!(h.table_targets(0), Some(&[3, 5][..]));
        assert_eq!(h.ref_func_targets(), &[5]);
        assert_eq!(h.origin_unit(0), Some(42));
        assert!(!h.global_is_read(2));
        assert!(h.global_is_read(3));
    }
}
