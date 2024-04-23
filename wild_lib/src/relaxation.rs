//! Contains code to perform various relocation relaxation optimisations. These are supposed to be
//! optional for the linker to do, but it turns out that libc in some cases won't work unless
//! they're performed. e.g. it uses GOT relocations in _start, which cannot work in a static-PIE
//! binary because dynamic relocations haven't yet been applied to the GOT yet.
//!
//! For now, we only apply those relaxations that we find we need.

use crate::args::OutputKind;
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

    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,

    /// Transform GD (general dynamic) into LE (local exec).
    TlsGdToLocalExec,

    /// Transform LD (local dynamic) into LE (local exec).
    TlsLdToLocalExec,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelocationModifier {
    Normal,
    SkipNextRelocation,
}

impl Relaxation {
    /// Tries to create a relaxation for the relocation of the specified kind, to be applied at the
    /// specified offset in the supplied section.
    pub(crate) fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        value_kind: ValueKind,
        output_kind: OutputKind,
    ) -> Option<(Self, u32)> {
        let offset = offset_in_section as usize;
        // TODO: Try fetching the symbol kind lazily. For most relocation, we don't need it, but
        // because fetching it contains potential error paths, the optimiser probably can't optimise
        // away fetching it.
        let (kind, new_rel) = match relocation_kind {
            object::elf::R_X86_64_REX_GOTPCRELX => {
                if offset < 3 {
                    return None;
                }
                let b1 = section_bytes[offset - 2];
                if section_bytes[offset - 3] != 0x48 {
                    return None;
                }
                let kind = match (b1, value_kind) {
                    (0x8b, ValueKind::Address) => {
                        (Relaxation::MovIndirectToLea, object::elf::R_X86_64_PC32)
                    }
                    (0x8b, ValueKind::Absolute) => {
                        (Relaxation::MovIndirectToAbsolute, object::elf::R_X86_64_32)
                    }
                    _ => return None,
                };
                return Some(kind);
            }
            object::elf::R_X86_64_GOTPCRELX => {
                if offset < 2 || value_kind != ValueKind::Address {
                    return None;
                }
                match section_bytes[offset - 2..offset] {
                    [0xff, 0x15] => (
                        Relaxation::CallIndirectToAbsolute,
                        object::elf::R_X86_64_PC32,
                    ),
                    _ => return None,
                }
            }
            object::elf::R_X86_64_GOTTPOFF => {
                if offset < 3 {
                    return None;
                }
                match section_bytes[offset - 3..offset - 1] {
                    [0x48, 0x8b] => (
                        Relaxation::MovIndirectToAbsolute,
                        object::elf::R_X86_64_DTPOFF32,
                    ),
                    _ => return None,
                }
            }
            object::elf::R_X86_64_PLT32 if output_kind == OutputKind::StaticExecutable => {
                return Some((Relaxation::NoOp, object::elf::R_X86_64_PC32));
            }
            object::elf::R_X86_64_TLSGD if output_kind == OutputKind::StaticExecutable => {
                if offset < 4 || section_bytes[offset - 4..offset] != [0x66, 0x48, 0x8d, 0x3d] {
                    return None;
                }
                (Relaxation::TlsGdToLocalExec, object::elf::R_X86_64_TPOFF32)
            }
            object::elf::R_X86_64_TLSLD if output_kind == OutputKind::StaticExecutable => {
                if offset < 3 || section_bytes[offset - 3..offset] != [0x48, 0x8d, 0x3d] {
                    return None;
                }
                (Relaxation::TlsLdToLocalExec, object::elf::R_X86_64_NONE)
            }

            _ => return None,
        };
        Some((kind, new_rel))
    }

    pub(crate) fn apply(
        &self,
        section_bytes: &mut [u8],
        offset_in_section: &mut u64,
        addend: &mut u64,
        next_modifier: &mut RelocationModifier,
    ) {
        let offset = *offset_in_section as usize;
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
            Relaxation::TlsGdToLocalExec => {
                section_bytes[offset - 4..offset + 8]
                    .copy_from_slice(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x8d, 0x80]);
                *offset_in_section += 8;
                *next_modifier = RelocationModifier::SkipNextRelocation;
            }
            Relaxation::TlsLdToLocalExec => {
                // Transforms to: mov %fs:0x0,%rax
                section_bytes[offset - 3..offset + 9]
                    .copy_from_slice(&[0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0]);
                *offset_in_section += 5;
                *next_modifier = RelocationModifier::SkipNextRelocation;
            }
            Relaxation::NoOp => {}
        }
    }
}

#[test]
fn test_relaxation() {
    #[track_caller]
    fn check(relocation_kind: u32, bytes_in: &[u8], address: &[u8], absolute: &[u8]) {
        let mut out = bytes_in.to_owned();
        let mut offset = bytes_in.len() as u64;
        let mut modifier = RelocationModifier::Normal;
        if let Some((r, _)) = Relaxation::new(
            relocation_kind,
            bytes_in,
            offset,
            ValueKind::Address,
            OutputKind::StaticExecutable,
        ) {
            r.apply(&mut out, &mut offset, &mut 0, &mut modifier);

            assert_eq!(
                out, address,
                "resolved: Expected {address:x?}, got {out:x?}"
            );
        }
        if let Some((r, _)) = Relaxation::new(
            relocation_kind,
            bytes_in,
            offset,
            ValueKind::Absolute,
            OutputKind::StaticExecutable,
        ) {
            out.copy_from_slice(bytes_in);
            r.apply(&mut out, &mut offset, &mut 0, &mut modifier);
            assert_eq!(
                out, absolute,
                "unresolved: Expected {absolute:x?}, got {out:x?}"
            );
        }
    }

    check(
        object::elf::R_X86_64_REX_GOTPCRELX,
        &[0x48, 0x8b, 0xae],
        &[0x48, 0x8d, 0xae],
        &[0x48, 0xc7, 0xc5],
    );
}
