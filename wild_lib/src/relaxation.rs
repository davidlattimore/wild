//! Contains code to perform various relocation relaxation optimisations. These are supposed to be
//! optional for the linker to do, but it turns out that libc in some cases won't work unless
//! they're performed. e.g. it uses GOT relocations in _start, which cannot work in a static-PIE
//! binary because dynamic relocations haven't yet been applied to the GOT yet.

use crate::args::OutputKind;
use crate::resolution::ValueFlag;
use crate::resolution::ValueFlags;

#[derive(Debug)]
pub(crate) enum Relaxation {
    /// Transforms a mov instruction that would have loaded an address to not use the GOT. The
    /// transformation will look like `mov *x(%rip), reg` -> `lea x(%rip), reg`.
    MovIndirectToLea,

    /// Transforms a mov instruction that would have loaded an absolute value to not use the GOT.
    /// The transformation will look like `mov *x(%rip), reg` ->  `mov x, reg`.
    MovIndirectToAbsolute,

    /// Transforms a mov instruction that would have loaded an absolute value to not use the GOT.
    /// The transformation will look like `mov *x(%rip), reg` ->  `mov x, reg`.
    RexMovIndirectToAbsolute,

    // Transforms an indirect sub to an absolute sub.
    RexSubIndirectToAbsolute,

    // Transforms an indirect cmp to an absolute cmp.
    RexCmpIndirectToAbsolute,

    /// Transform a call instruction like `call *x(%rip)` -> `call x(%rip)`.
    CallIndirectToRelative,

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
        value_flags: ValueFlags,
        output_kind: OutputKind,
    ) -> Option<(Self, u32)> {
        let is_known_address = value_flags.contains(ValueFlag::Address);
        let is_absolute = value_flags.contains(ValueFlag::Absolute);
        let non_relocatable = output_kind == OutputKind::NonRelocatableStaticExecutable;
        let is_absolute_address = is_known_address && non_relocatable;
        let can_be_pc_relative = is_known_address || (is_absolute && non_relocatable);

        // IFuncs cannot be referenced directly. The always need to go via the GOT. So if we've got
        // say a PLT32 relocation, we don't want to relax it even if we're in a static executable.
        // Furthermore, if we encounter a relocation like PC32 to an ifunc, then we need to change
        // it so that it goes via the GOT. This is kind of the opposite of relaxation.
        if value_flags.contains(ValueFlag::IFunc) {
            return match relocation_kind {
                object::elf::R_X86_64_PC32 => Some((Relaxation::NoOp, object::elf::R_X86_64_PLT32)),
                _ => None,
            };
        }

        let can_bypass_got = value_flags.contains(ValueFlag::CanBypassGot);

        let offset = offset_in_section as usize;
        // TODO: Try fetching the symbol kind lazily. For most relocation, we don't need it, but
        // because fetching it contains potential error paths, the optimiser probably can't optimise
        // away fetching it.
        match relocation_kind {
            object::elf::R_X86_64_REX_GOTPCRELX => {
                if offset < 3 {
                    return None;
                }
                let b1 = section_bytes[offset - 2];
                let rex = section_bytes[offset - 3];
                if rex != 0x48 && rex != 0x4c {
                    return None;
                }
                if is_absolute || is_absolute_address {
                    match b1 {
                        0x8b => {
                            return Some((
                                Relaxation::RexMovIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            ));
                        }
                        0x2b => {
                            return Some((
                                Relaxation::RexSubIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            ));
                        }
                        0x3b => {
                            return Some((
                                Relaxation::RexCmpIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            ));
                        }
                        _ => return None,
                    }
                } else if can_be_pc_relative {
                    match b1 {
                        0x8b => {
                            return Some((
                                Relaxation::MovIndirectToLea,
                                object::elf::R_X86_64_PC32,
                            ));
                        }
                        _ => return None,
                    }
                }
            }
            object::elf::R_X86_64_GOTPCRELX => {
                if offset < 2 {
                    return None;
                }
                if is_absolute || is_absolute_address {
                    match section_bytes[offset - 2] {
                        0x8b => {
                            return Some((
                                Relaxation::MovIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            ));
                        }
                        _ => {}
                    }
                }
                if can_be_pc_relative {
                    match &section_bytes[offset - 2..offset] {
                        [0xff, 0x15] => {
                            return Some((
                                Relaxation::CallIndirectToRelative,
                                object::elf::R_X86_64_PC32,
                            ))
                        }
                        _ => return None,
                    }
                }
                return None;
            }
            object::elf::R_X86_64_GOTPCREL if can_be_pc_relative && offset >= 2 => {
                let b1 = section_bytes[offset - 2];
                match b1 {
                    0x8b => {
                        return Some((Relaxation::MovIndirectToLea, object::elf::R_X86_64_PC32));
                    }
                    _ => {}
                }
                return None;
            }
            object::elf::R_X86_64_GOTTPOFF => {
                if offset < 3 {
                    return None;
                }
                match section_bytes[offset - 3..offset - 1] {
                    [0x48 | 0x4c, 0x8b] => {
                        return Some((
                            Relaxation::RexMovIndirectToAbsolute,
                            object::elf::R_X86_64_TPOFF32,
                        ))
                    }
                    _ => {}
                }
            }
            object::elf::R_X86_64_PLT32 if can_bypass_got => {
                return Some((Relaxation::NoOp, object::elf::R_X86_64_PC32));
            }
            object::elf::R_X86_64_TLSGD if output_kind.is_static_executable() => {
                if offset < 4 || section_bytes[offset - 4..offset] != [0x66, 0x48, 0x8d, 0x3d] {
                    return None;
                }
                return Some((Relaxation::TlsGdToLocalExec, object::elf::R_X86_64_TPOFF32));
            }
            object::elf::R_X86_64_TLSLD if output_kind.is_executable() => {
                if offset < 3 || section_bytes[offset - 3..offset] != [0x48, 0x8d, 0x3d] {
                    return None;
                }
                return Some((Relaxation::TlsLdToLocalExec, object::elf::R_X86_64_NONE));
            }

            _ => return None,
        };
        None
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
            Relaxation::RexMovIndirectToAbsolute => {
                // Turn a PC-relative mov into an absolute mov.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0xc7;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xc0;
                *addend = 0;
            }
            Relaxation::RexSubIndirectToAbsolute => {
                // Turn a PC-relative sub into an absolute sub.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0x81;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xe8;
                *addend = 0;
            }
            Relaxation::RexCmpIndirectToAbsolute => {
                // Turn a PC-relative cmp into an absolute cmp.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0x81;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xf8;
                *addend = 0;
            }
            Relaxation::CallIndirectToRelative => {
                section_bytes[offset - 2..offset].copy_from_slice(&[0x67, 0xe8]);
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
            ValueFlag::Address.into(),
            OutputKind::PositionIndependentStaticExecutable,
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
            ValueFlag::Absolute.into(),
            OutputKind::PositionIndependentStaticExecutable,
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
