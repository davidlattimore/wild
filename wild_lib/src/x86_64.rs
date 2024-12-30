//! Contains x86_64-specific code to perform various relocation relaxation optimisations. These are
//! supposed to be optional for the linker to do, but it turns out that libc in some cases won't
//! work unless they're performed. e.g. it uses GOT relocations in _start, which cannot work in a
//! static-PIE binary because dynamic relocations haven't yet been applied to the GOT yet.

use crate::arch::Arch;
use crate::args::OutputKind;
use crate::elf::DynamicRelocationKind;
use crate::elf::RelocationKind;
use crate::elf::RelocationKindInfo;
use crate::elf::RelocationSize;
use crate::relaxation::RelocationModifier;
use crate::resolution::ValueFlags;
use anyhow::bail;
use anyhow::Result;
use linker_utils::elf::shf;
use linker_utils::elf::x86_64_rel_type_to_string;
use linker_utils::elf::SectionFlags;

pub(crate) struct X86_64;

impl crate::arch::Arch for X86_64 {
    type Relaxation = Relaxation;

    fn elf_header_arch_magic() -> u16 {
        object::elf::EM_X86_64
    }

    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        let (kind, size) = match r_type {
            object::elf::R_X86_64_64 => (RelocationKind::Absolute, 8),
            object::elf::R_X86_64_PC32 => (RelocationKind::Relative, 4),
            object::elf::R_X86_64_PC64 => (RelocationKind::Relative, 8),
            object::elf::R_X86_64_GOT32 => (RelocationKind::GotRelGotBase, 4),
            object::elf::R_X86_64_GOT64 => (RelocationKind::GotRelGotBase, 8),
            object::elf::R_X86_64_GOTOFF64 => (RelocationKind::SymRelGotBase, 8),
            object::elf::R_X86_64_PLT32 => (RelocationKind::PltRelative, 4),
            object::elf::R_X86_64_PLTOFF64 => (RelocationKind::PltRelGotBase, 8),
            object::elf::R_X86_64_GOTPCREL => (RelocationKind::GotRelative, 4),

            // For now, we rely on GOTPC64 and GOTPC32 always referencing the symbol
            // _GLOBAL_OFFSET_TABLE_, which means that we can just treat these a normal relative
            // relocations and avoid any special processing when writing.
            object::elf::R_X86_64_GOTPC64 => (RelocationKind::Relative, 8),
            object::elf::R_X86_64_GOTPC32 => (RelocationKind::Relative, 4),

            object::elf::R_X86_64_32 | object::elf::R_X86_64_32S => (RelocationKind::Absolute, 4),
            object::elf::R_X86_64_16 => (RelocationKind::Absolute, 2),
            object::elf::R_X86_64_PC16 => (RelocationKind::Relative, 2),
            object::elf::R_X86_64_8 => (RelocationKind::Absolute, 1),
            object::elf::R_X86_64_PC8 => (RelocationKind::Relative, 1),
            object::elf::R_X86_64_TLSGD => (RelocationKind::TlsGd, 4),
            object::elf::R_X86_64_TLSLD => (RelocationKind::TlsLd, 4),
            object::elf::R_X86_64_DTPOFF32 => (RelocationKind::DtpOff, 4),
            object::elf::R_X86_64_DTPOFF64 => (RelocationKind::DtpOff, 8),
            object::elf::R_X86_64_GOTTPOFF => (RelocationKind::GotTpOff, 4),
            object::elf::R_X86_64_GOTPCRELX | object::elf::R_X86_64_REX_GOTPCRELX => {
                (RelocationKind::GotRelative, 4)
            }
            object::elf::R_X86_64_TPOFF32 => (RelocationKind::TpOff, 4),
            object::elf::R_X86_64_NONE => (RelocationKind::None, 0),
            _ => bail!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            ),
        };
        Ok(RelocationKindInfo {
            kind,
            size: RelocationSize::ByteSize(size),
            mask: None,
        })
    }

    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32 {
        match relocation {
            DynamicRelocationKind::Copy => object::elf::R_X86_64_COPY,
            DynamicRelocationKind::Irelative => object::elf::R_X86_64_IRELATIVE,
            DynamicRelocationKind::DtpMod => object::elf::R_X86_64_DTPMOD64,
            DynamicRelocationKind::DtpOff => object::elf::R_X86_64_DTPOFF64,
            DynamicRelocationKind::TpOff => object::elf::R_X86_64_TPOFF64,
            DynamicRelocationKind::Relative => object::elf::R_X86_64_RELATIVE,
            DynamicRelocationKind::DynamicSymbol => object::elf::R_X86_64_GLOB_DAT,
        }
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        x86_64_rel_type_to_string(r_type)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
}

#[derive(Debug, Clone, Copy)]
enum RelaxationKind {
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

    /// Transform general dynamic (GD) into local exec.
    TlsGdToLocalExec,

    /// As above, but for the large-model form of the instruction.
    TlsGdToLocalExecLarge,

    /// Transform local dynamic (LD) into local exec.
    TlsLdToLocalExec,

    /// Transform general dynamic (GD) into initial exec
    TlsGdToInitialExec,
}

impl crate::arch::Relaxation for Relaxation {
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        value_flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: SectionFlags,
    ) -> Option<Self> {
        // TODO: Consider removing Option. There are a few callers though, so need to see how this
        // looks.
        #[allow(clippy::unnecessary_wraps)]
        fn create(kind: RelaxationKind, new_r_type: u32) -> Option<Relaxation> {
            // This only fails for relocation types that we don't support and if we relax to a type
            // we don't support, then that's a bug.
            let rel_info = X86_64::relocation_from_raw(new_r_type).unwrap();
            Some(Relaxation { kind, rel_info })
        }

        let is_known_address = value_flags.contains(ValueFlags::ADDRESS);
        let is_absolute = value_flags.contains(ValueFlags::ABSOLUTE)
            && !value_flags.contains(ValueFlags::DYNAMIC);
        let non_relocatable = !output_kind.is_relocatable();
        let is_absolute_address = is_known_address && non_relocatable;
        let can_bypass_got = value_flags.contains(ValueFlags::CAN_BYPASS_GOT);

        // IFuncs cannot be referenced directly. The always need to go via the GOT. So if we've got
        // say a PLT32 relocation, we don't want to relax it even if we're in a static executable.
        // Furthermore, if we encounter a relocation like PC32 to an ifunc, then we need to change
        // it so that it goes via the GOT. This is kind of the opposite of relaxation.
        if value_flags.contains(ValueFlags::IFUNC) {
            return match relocation_kind {
                object::elf::R_X86_64_PC32 => {
                    return create(RelaxationKind::NoOp, object::elf::R_X86_64_PLT32);
                }
                _ => None,
            };
        }

        // All relaxations below only apply to executable code, so we shouldn't attempt them if a
        // relocation is in a non-executable section.
        if !section_flags.contains(shf::EXECINSTR) {
            return None;
        }

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
                            return create(
                                RelaxationKind::RexMovIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            );
                        }
                        0x2b => {
                            return create(
                                RelaxationKind::RexSubIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            );
                        }
                        0x3b => {
                            return create(
                                RelaxationKind::RexCmpIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            );
                        }
                        _ => return None,
                    }
                } else if can_bypass_got {
                    match b1 {
                        0x8b => {
                            return create(
                                RelaxationKind::MovIndirectToLea,
                                object::elf::R_X86_64_PC32,
                            );
                        }
                        _ => return None,
                    }
                }
            }
            object::elf::R_X86_64_GOTPCRELX => {
                if is_absolute || is_absolute_address {
                    match section_bytes.get(offset - 2)? {
                        0x8b => {
                            return create(
                                RelaxationKind::MovIndirectToAbsolute,
                                object::elf::R_X86_64_32,
                            );
                        }
                        _ => {}
                    }
                }
                if can_bypass_got {
                    match section_bytes.get(offset - 2..offset)? {
                        [0xff, 0x15] => {
                            return create(
                                RelaxationKind::CallIndirectToRelative,
                                object::elf::R_X86_64_PC32,
                            )
                        }
                        _ => return None,
                    }
                }
                return None;
            }
            object::elf::R_X86_64_GOTPCREL if can_bypass_got && offset >= 2 => {
                match section_bytes.get(offset - 2)? {
                    0x8b => {
                        return create(
                            RelaxationKind::MovIndirectToLea,
                            object::elf::R_X86_64_PC32,
                        );
                    }
                    _ => {}
                }
                return None;
            }
            object::elf::R_X86_64_GOTTPOFF if can_bypass_got => {
                match section_bytes.get(offset - 3..offset - 1)? {
                    [0x48 | 0x4c, 0x8b] => {
                        return create(
                            RelaxationKind::RexMovIndirectToAbsolute,
                            object::elf::R_X86_64_TPOFF32,
                        )
                    }
                    _ => {}
                }
            }
            object::elf::R_X86_64_PLT32 if can_bypass_got => {
                return create(RelaxationKind::NoOp, object::elf::R_X86_64_PC32);
            }
            object::elf::R_X86_64_PLTOFF64 if can_bypass_got => {
                return create(RelaxationKind::NoOp, object::elf::R_X86_64_GOTOFF64);
            }
            object::elf::R_X86_64_TLSGD if can_bypass_got && output_kind.is_executable() => {
                let kind = match TlsGdForm::identify(section_bytes, offset)? {
                    TlsGdForm::Regular => RelaxationKind::TlsGdToLocalExec,
                    TlsGdForm::Large => RelaxationKind::TlsGdToLocalExecLarge,
                };
                return create(kind, object::elf::R_X86_64_TPOFF32);
            }
            object::elf::R_X86_64_TLSGD if output_kind.is_executable() => {
                let kind = match TlsGdForm::identify(section_bytes, offset)? {
                    TlsGdForm::Regular => RelaxationKind::TlsGdToInitialExec,
                    TlsGdForm::Large => {
                        // TODO
                        return None;
                    }
                };
                return create(kind, object::elf::R_X86_64_GOTTPOFF);
            }
            object::elf::R_X86_64_TLSLD if output_kind.is_executable() => {
                if section_bytes.get(offset - 3..offset)? == [0x48, 0x8d, 0x3d] {
                    return create(RelaxationKind::TlsLdToLocalExec, object::elf::R_X86_64_NONE);
                }
            }
            _ => return None,
        };
        None
    }

    fn apply(
        &self,
        section_bytes: &mut [u8],
        offset_in_section: &mut u64,
        addend: &mut u64,
        next_modifier: &mut RelocationModifier,
    ) {
        let offset = *offset_in_section as usize;
        match self.kind {
            RelaxationKind::MovIndirectToLea => {
                // Since the value is an address, we transform a PC-relative mov into a PC-relative
                // lea.
                section_bytes[offset - 2] = 0x8d;
            }
            RelaxationKind::MovIndirectToAbsolute => {
                // Turn a PC-relative mov into an absolute mov.
                section_bytes[offset - 2] = 0xc7;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xc0;
                *addend = 0;
            }
            RelaxationKind::RexMovIndirectToAbsolute => {
                // Turn a PC-relative mov into an absolute mov.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0xc7;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xc0;
                *addend = 0;
            }
            RelaxationKind::RexSubIndirectToAbsolute => {
                // Turn a PC-relative sub into an absolute sub.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0x81;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xe8;
                *addend = 0;
            }
            RelaxationKind::RexCmpIndirectToAbsolute => {
                // Turn a PC-relative cmp into an absolute cmp.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0x81;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xf8;
                *addend = 0;
            }
            RelaxationKind::CallIndirectToRelative => {
                section_bytes[offset - 2..offset].copy_from_slice(&[0x67, 0xe8]);
            }
            RelaxationKind::TlsGdToLocalExec => {
                section_bytes[offset - 4..offset + 8].copy_from_slice(&[
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0,%rax
                    0x48, 0x8d, 0x80, // lea {offset}(%rax),%rax
                ]);
                *offset_in_section += 8;
                *addend = 0;
                *next_modifier = RelocationModifier::SkipNextRelocation;
            }
            RelaxationKind::TlsGdToLocalExecLarge => {
                section_bytes[offset - 3..offset + 19].copy_from_slice(&[
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0,%rax
                    0x48, 0x8d, 0x80, 0, 0, 0, 0, // lea {offset}(%rax),%rax
                    0x66, 0x0f, 0x1f, 0x44, 0, 0, // nopw (%rax,%rax)
                ]);
                *offset_in_section += 9;
                *addend = 0;
                *next_modifier = RelocationModifier::SkipNextRelocation;
            }
            RelaxationKind::TlsGdToInitialExec => {
                section_bytes[offset - 4..offset + 8]
                    .copy_from_slice(&[0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, 0x48, 0x03, 0x05]);
                *offset_in_section += 8;
                *addend = -12_i64 as u64;
                *next_modifier = RelocationModifier::SkipNextRelocation;
            }
            RelaxationKind::TlsLdToLocalExec => {
                // Transforms to: `mov %fs:0x0,%rax` with some amount of padding depending on
                // whether the subsequent instruction is 64 bit (first) or 32 bit (second).
                if section_bytes.get(offset + 4..offset + 6) == Some(&[0x48, 0xb8]) {
                    section_bytes[offset - 3..offset + 19].copy_from_slice(&[
                        // nopw (%rax,%rax)
                        0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0,
                        // mov %fs:0,%rax
                        0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
                    ]);
                    *offset_in_section += 15;
                } else {
                    section_bytes[offset - 3..offset + 9].copy_from_slice(&[
                        0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
                    ]);
                    *offset_in_section += 5;
                }
                *next_modifier = RelocationModifier::SkipNextRelocation;
            }
            RelaxationKind::NoOp => {}
        }
    }

    fn rel_info(&self) -> crate::elf::RelocationKindInfo {
        self.rel_info
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        &self.kind
    }
}

enum TlsGdForm {
    Regular,
    Large,
}

impl TlsGdForm {
    fn identify(bytes: &[u8], offset: usize) -> Option<Self> {
        if bytes.get(offset - 4..offset) == Some(&[0x66, 0x48, 0x8d, 0x3d])
            && bytes.get(offset + 4..offset + 8) == Some(&[0x66, 0x66, 0x48, 0xe8])
        {
            Some(Self::Regular)
        } else if bytes.get(offset - 3..offset) == Some(&[0x48, 0x8d, 0x3d])
            && bytes.get(offset + 4..offset + 6) == Some(&[0x48, 0xb8])
            && bytes.get(offset + 14..offset + 19) == Some(&[0x48, 0x01, 0xd8, 0xff, 0xd0])
        {
            Some(Self::Large)
        } else {
            None
        }
    }
}

#[test]
fn test_relaxation() {
    use crate::arch::Relaxation as _;
    use crate::args::RelocationModel;

    #[track_caller]
    fn check(relocation_kind: u32, bytes_in: &[u8], address: &[u8], absolute: &[u8]) {
        let mut out = bytes_in.to_owned();
        let mut offset = bytes_in.len() as u64;
        let mut modifier = RelocationModifier::Normal;
        if let Some(r) = Relaxation::new(
            relocation_kind,
            bytes_in,
            offset,
            ValueFlags::ADDRESS,
            OutputKind::StaticExecutable(RelocationModel::Relocatable),
            shf::EXECINSTR,
        ) {
            r.apply(&mut out, &mut offset, &mut 0, &mut modifier);

            assert_eq!(
                out, address,
                "resolved: Expected {address:x?}, got {out:x?}"
            );
        }
        if let Some(r) = Relaxation::new(
            relocation_kind,
            bytes_in,
            offset,
            ValueFlags::ABSOLUTE,
            OutputKind::StaticExecutable(RelocationModel::Relocatable),
            shf::EXECINSTR,
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
