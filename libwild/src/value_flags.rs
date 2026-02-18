use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use bitflags::bitflags;
use object::read::elf::Sym as _;
use std::sync::atomic;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use zerocopy::FromBytes;
use zerocopy::IntoBytes;
use zerocopy::transmute_mut;

/// A raw representation of `ValueFlags`. This is separate from `ValueFlags` so that we can derive
/// `FromBytes` and `IntoBytes`.
#[derive(derive_more::Debug, Clone, Copy, PartialEq, Eq, Hash, FromBytes, IntoBytes)]
#[debug("{}", ValueFlags::from_bits_retain(*_0))]
pub(crate) struct RawFlags(u16);

/// Flags for each symbol.
#[derive(Debug)]
pub(crate) struct PerSymbolFlags {
    pub(crate) flags: Vec<RawFlags>,
}

// Flags for each symbol where we can perform atomic updates via a shared reference.
pub(crate) struct AtomicPerSymbolFlags<'a> {
    flags: &'a [AtomicValueFlags],
}

bitflags! {
    /// Information and state of a symbol or section. Some of this information comes from the object
    /// that defined the symbol or section and some is computed based on what kinds of references we
    /// encounter to it.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct ValueFlags: u16 {
        /// An absolute value that won't change depending on load address. This could be a symbol
        /// with an absolute value or an undefined symbol, which needs to always resolve to 0
        /// regardless of load address.
        const ABSOLUTE = 1 << 0;

        /// The value is from a shared (dynamic) object, so although it may have an address, it
        /// won't be known until runtime. If combined with `ABSOLUTE`, then the symbol isn't
        /// actually defined by any shared object. We'll emit a dynamic relocation for it on a
        /// best-effort basis only. e.g. if there are direct references to it from a read-only
        /// section we'll fill them in as zero.
        const DYNAMIC = 1 << 1;

        /// The value refers to an ifunc. The actual address won't be known until runtime.
        const IFUNC = 1 << 2;

        /// Whether the definition of the symbol is final and cannot be overridden at runtime.
        const NON_INTERPOSABLE = 1 << 3;

        /// We have a version script and the version script says that the symbol should be downgraded to
        /// a local. It's still treated as a global for name lookup purposes, but after that, it becomes
        /// local.
        const DOWNGRADE_TO_LOCAL = 1 << 4;

        /// Set when the value is a function. Currently only set for dynamic symbols, since that's
        /// all we need it for.
        const FUNCTION = 1 << 5;

        /// The direct value is needed. e.g. via a relative or absolute relocation that doesn't use the
        /// PLT or GOT.
        const DIRECT = 1 << 6;

        /// An address in the global offset table is needed.
        const GOT = 1 << 7;

        /// A PLT entry is needed.
        const PLT = 1 << 8;

        /// A double GOT entry is needed in order to store the module number and offset within the
        /// module. Only set for TLS variables.
        const GOT_TLS_MODULE = 1 << 9;

        /// A single GOT entry is needed to store the offset of the TLS variable within the initial
        /// TLS block.
        const GOT_TLS_OFFSET = 1 << 10;

        /// A double GOT entry is needed in order to store the function pointer and a pointer that
        /// points to a pair of words (module number and offset within the module).
        /// Only set for TLS variables.
        const GOT_TLS_DESCRIPTOR = 1 << 11;

        /// The request originated from a dynamic object, so the symbol should be put into the dynamic
        /// symbol table.
        const EXPORT_DYNAMIC = 1 << 12;

        /// We encountered a direct reference to a symbol from a non-writable section and so we're
        /// going to need to do a copy relocation. Note that multiple symbols can have this flag
        /// set, however if they all point at the same address in the shared object from which they
        /// originate, only a single copy relocation will be emitted. This flag indicates that the
        /// symbol requires a copy relocation, not necessarily that a copy relocation will be
        /// emitted with the exact name of this symbol.
        const COPY_RELOCATION = 1 << 13;

        /// A GOT entry is needed for address equality of an IFUNC symbol. When code takes the
        /// address of an IFUNC via a GOT-relative relocation, we need a separate GOT entry that
        /// contains the PLT stub address (for address equality), rather than the IRELATIVE GOT
        /// entry which will be resolved to the actual function address at runtime.
        const IFUNC_GOT_FOR_ADDRESS = 1 << 14;
    }
}

#[derive(FromBytes, IntoBytes)]
pub(crate) struct AtomicValueFlags(AtomicU16);

impl ValueFlags {
    /// Returns self merged with `other` which should be the flags for the local (possibly
    /// non-canonical symbol definition). Sometimes an object will reference a symbol that it
    /// doesn't define and will mark that symbol as hidden, however the object that defines the
    /// symbol gives the symbol default visibility. In this case, we want references in the object
    /// defining it as hidden to be allowed to bypass the GOT/PLT.
    pub(crate) fn merge(&mut self, other: ValueFlags) {
        if other.contains(ValueFlags::NON_INTERPOSABLE) {
            *self |= ValueFlags::NON_INTERPOSABLE;
        }
    }

    /// Returns the subset of the set flags that relate to resolutions.
    pub(crate) fn resolution_flags(self) -> ValueFlags {
        self.intersection(
            ValueFlags::DIRECT
                | ValueFlags::GOT
                | ValueFlags::PLT
                | ValueFlags::GOT_TLS_MODULE
                | ValueFlags::GOT_TLS_OFFSET
                | ValueFlags::GOT_TLS_DESCRIPTOR
                | ValueFlags::EXPORT_DYNAMIC
                | ValueFlags::COPY_RELOCATION
                | ValueFlags::IFUNC_GOT_FOR_ADDRESS,
        )
    }

    #[must_use]
    pub(crate) fn has_resolution(self) -> bool {
        !self.resolution_flags().is_empty()
    }

    #[must_use]
    pub(crate) fn is_dynamic(self) -> bool {
        self.contains(ValueFlags::DYNAMIC)
    }

    #[must_use]
    pub(crate) fn is_ifunc(self) -> bool {
        self.contains(ValueFlags::IFUNC)
    }

    /// Returns whether the value will have an address that is known at link time. This is as
    /// opposed to things where the address cannot be known until runtime or absolute values, which
    /// aren't addresses.
    #[must_use]
    pub(crate) fn is_address(self) -> bool {
        !self.contains(ValueFlags::IFUNC)
            && !self.contains(ValueFlags::DYNAMIC)
            && !self.contains(ValueFlags::ABSOLUTE)
    }

    #[must_use]
    pub(crate) fn is_absolute(self) -> bool {
        self.contains(ValueFlags::ABSOLUTE)
    }

    #[must_use]
    pub(crate) fn is_function(self) -> bool {
        self.contains(ValueFlags::FUNCTION)
    }
    #[must_use]
    pub(crate) fn is_downgraded_to_local(self) -> bool {
        self.contains(ValueFlags::DOWNGRADE_TO_LOCAL)
    }

    /// Returns true if a symbol should be treated as local in the symbol table.
    /// This includes both originally-local symbols and symbols downgraded by version scripts.
    #[must_use]
    pub(crate) fn is_symtab_local(self, sym: &crate::elf::Symbol) -> bool {
        sym.is_local() || self.is_downgraded_to_local()
    }

    #[must_use]
    pub(crate) fn is_interposable(self) -> bool {
        !self.contains(ValueFlags::NON_INTERPOSABLE)
    }

    #[must_use]
    pub(crate) fn needs_direct(self) -> bool {
        self.contains(ValueFlags::DIRECT)
    }

    #[must_use]
    pub(crate) fn needs_copy_relocation(self) -> bool {
        self.contains(ValueFlags::COPY_RELOCATION)
    }

    #[must_use]
    pub(crate) fn needs_export_dynamic(self) -> bool {
        self.contains(ValueFlags::EXPORT_DYNAMIC)
    }

    #[must_use]
    pub(crate) fn needs_got(self) -> bool {
        self.contains(ValueFlags::GOT)
    }

    #[must_use]
    pub(crate) fn needs_plt(self) -> bool {
        self.contains(ValueFlags::PLT)
    }

    #[must_use]
    pub(crate) fn needs_got_tls_offset(self) -> bool {
        self.contains(ValueFlags::GOT_TLS_OFFSET)
    }

    #[must_use]
    pub(crate) fn needs_got_tls_module(self) -> bool {
        self.contains(ValueFlags::GOT_TLS_MODULE)
    }

    #[must_use]
    pub(crate) fn needs_got_tls_descriptor(self) -> bool {
        self.contains(ValueFlags::GOT_TLS_DESCRIPTOR)
    }

    #[must_use]
    pub(crate) fn needs_ifunc_got_for_address(self) -> bool {
        self.contains(ValueFlags::IFUNC_GOT_FOR_ADDRESS)
    }

    #[must_use]
    pub(crate) fn is_tls(self) -> bool {
        self.contains(ValueFlags::GOT_TLS_OFFSET)
            || self.contains(ValueFlags::GOT_TLS_MODULE)
            || self.contains(ValueFlags::GOT_TLS_DESCRIPTOR)
    }

    #[must_use]
    pub(crate) fn raw(self) -> RawFlags {
        RawFlags(self.bits())
    }
}

impl AtomicValueFlags {
    pub(crate) fn fetch_or(&self, flags: ValueFlags) -> ValueFlags {
        // Calling fetch_or on our atomic requires that we gain exclusive access to the cache line
        // containing the atomic. If all the bits are already set, then that's wasteful, so we first
        // check if the bits are set and if they are, we skip the fetch_or call.
        let current_bits = self.0.load(atomic::Ordering::Relaxed);
        if current_bits & flags.bits() == flags.bits() {
            return ValueFlags::from_bits_retain(current_bits);
        }
        let previous_bits = self.0.fetch_or(flags.bits(), atomic::Ordering::Relaxed);
        ValueFlags::from_bits_retain(previous_bits)
    }

    pub(crate) fn get(&self) -> ValueFlags {
        ValueFlags::from_bits_retain(self.0.load(atomic::Ordering::Relaxed))
    }

    pub(crate) fn or_assign(&self, flags: ValueFlags) {
        self.0.fetch_or(flags.bits(), Ordering::Relaxed);
    }

    pub(crate) fn remove(&self, flags_to_remove: ValueFlags) {
        self.0.fetch_and(!flags_to_remove.bits(), Ordering::Relaxed);
    }
}

impl std::fmt::Display for ValueFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

impl PerSymbolFlags {
    pub(crate) fn new() -> Self {
        Self { flags: Vec::new() }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        self.flags.reserve(additional);
    }

    pub(crate) fn borrow_atomic(&'_ mut self) -> AtomicPerSymbolFlags<'_> {
        AtomicPerSymbolFlags {
            flags: transmute_mut!(self.flags.as_mut_slice()),
        }
    }

    pub(crate) fn raw_range(&self, range: SymbolIdRange) -> &[RawFlags] {
        &self.flags[range.as_usize()]
    }

    pub(crate) fn push(&mut self, extra: ValueFlags) {
        self.flags.push(extra.raw());
    }

    pub(crate) fn set_flag(&mut self, symbol_id: SymbolId, extra: ValueFlags) {
        self.flags[symbol_id.as_usize()].0 |= extra.raw().0;
    }

    pub(crate) fn flags_mut(&mut self) -> &mut [RawFlags] {
        &mut self.flags
    }
}

impl<'a> AtomicPerSymbolFlags<'a> {
    pub(crate) fn get_atomic(&self, symbol_id: SymbolId) -> &AtomicValueFlags {
        &self.flags[symbol_id.as_usize()]
    }

    pub(crate) fn range(&self, range: SymbolIdRange) -> &[AtomicValueFlags] {
        &self.flags[range.as_usize()]
    }
}

impl RawFlags {
    pub(crate) fn get(self) -> ValueFlags {
        ValueFlags::from_bits_retain(self.0)
    }
}

pub(crate) trait FlagsForSymbol {
    fn flags_for_symbol(&self, symbol_id: SymbolId) -> ValueFlags;
}

impl FlagsForSymbol for PerSymbolFlags {
    fn flags_for_symbol(&self, symbol_id: SymbolId) -> ValueFlags {
        self.flags[symbol_id.as_usize()].get()
    }
}

impl FlagsForSymbol for AtomicPerSymbolFlags<'_> {
    fn flags_for_symbol(&self, symbol_id: SymbolId) -> ValueFlags {
        self.flags[symbol_id.as_usize()].get()
    }
}
