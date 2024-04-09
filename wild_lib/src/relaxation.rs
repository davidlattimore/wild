//! Contains code to perform various relocation relaxation optimisations. These are supposed to be
//! optional for the linker to do, but it turns out that libc in some cases won't work unless
//! they're performed. e.g. it uses GOT relocations in _start, which cannot work in a static-PIE
//! binary because dynamic relocations haven't yet been applied to the GOT yet.
//!
//! For now, we only apply those relaxations that we find we need.

use crate::elf::rel;
use crate::resolution::ValueKind;

#[derive(Debug)]
pub(crate) enum Relaxation {
    /// Transforms a mov instruction that would have loaded an address to not use the GOT. The
    /// transformation will look like `mov *x(%rip), reg` -> `lea x(%rip), reg`.
    MovIndirectToLea,

    /// Transforms a mov instruction that would have loaded an absolute value to not use the GOT.
    /// The transformation will look like `mov *x(%rip), reg` ->  `mov x, reg`.
    MovIndirectToAbsolute,

    /// Transform a call instruction like `call *x(%rip)` -> `call x(%rip)`.
    CallIndirectToAbsolute,
}

impl Relaxation {
    /// Tries to create a relaxation for the relocation of the specified kind, to be applied at the
    /// specified offset in the supplied section.
    pub(crate) fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset: usize,
        value_kind: ValueKind,
    ) -> Option<(Self, u32)> {
        // TODO: Try fetching the symbol kind lazily. For most relocation, we don't need it, but
        // because fetching it contains potential error paths, the optimiser probably can't optimise
        // away fetching it.
        let (kind, new_rel) = match relocation_kind {
            rel::R_X86_64_REX_GOTPCRELX => {
                if offset < 3 {
                    return None;
                }
                let b1 = section_bytes[offset - 2];
                if section_bytes[offset - 3] != 0x48 {
                    return None;
                }
                let kind = match (b1, value_kind) {
                    (0x8b, ValueKind::Address) => {
                        (Relaxation::MovIndirectToLea, rel::R_X86_64_PC32)
                    }
                    (0x8b, ValueKind::Absolute) => {
                        (Relaxation::MovIndirectToAbsolute, rel::R_X86_64_32)
                    }
                    _ => return None,
                };
                return Some(kind);
            }
            rel::R_X86_64_GOTPCRELX => {
                if offset < 2 || value_kind != ValueKind::Address {
                    return None;
                }
                match section_bytes[offset - 2..offset] {
                    [0xff, 0x15] => (Relaxation::CallIndirectToAbsolute, rel::R_X86_64_PC32),
                    _ => return None,
                }
            }
            rel::R_X86_64_GOTTPOFF => {
                if offset < 3 {
                    return None;
                }
                match section_bytes[offset - 3..offset - 1] {
                    [0x48, 0x8b] => (Relaxation::MovIndirectToAbsolute, rel::R_X86_64_DTPOFF32),
                    _ => return None,
                }
            }
            _ => return None,
        };
        Some((kind, new_rel))
    }

    pub(crate) fn apply(&self, section_bytes: &mut [u8], offset: usize, addend: &mut u64) {
        match self {
            Relaxation::MovIndirectToLea => {
                // Since the value is an address, we transform a PC-relative mov into a PC-relative
                // lea.
                section_bytes[offset - 2] = 0x8d;
            }
            Relaxation::MovIndirectToAbsolute => {
                // Turn a PC-relative mov into an absolute mov.
                section_bytes[offset - 2] = 0xc7;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xc0;
                *addend = 0;
            }
            Relaxation::CallIndirectToAbsolute => {
                section_bytes[offset - 2..offset].copy_from_slice(&[0x67, 0xe8]);
                *addend = 0;
            }
        }
    }
}

#[test]
fn test_relaxation() {
    #[track_caller]
    fn check(relocation_kind: u32, bytes_in: &[u8], address: &[u8], absolute: &[u8]) {
        let mut out = bytes_in.to_owned();
        let offset = bytes_in.len();
        if let Some((r, _)) = Relaxation::new(relocation_kind, bytes_in, offset, ValueKind::Address)
        {
            r.apply(&mut out, offset, &mut 0);

            assert_eq!(
                out, address,
                "resolved: Expected {address:x?}, got {out:x?}"
            );
        }
        if let Some((r, _)) =
            Relaxation::new(relocation_kind, bytes_in, offset, ValueKind::Absolute)
        {
            out.copy_from_slice(bytes_in);
            r.apply(&mut out, offset, &mut 0);
            assert_eq!(
                out, absolute,
                "unresolved: Expected {absolute:x?}, got {out:x?}"
            );
        }
    }

    check(
        rel::R_X86_64_REX_GOTPCRELX,
        &[0x48, 0x8b, 0xae],
        &[0x48, 0x8d, 0xae],
        &[0x48, 0xc7, 0xc5],
    );
}
