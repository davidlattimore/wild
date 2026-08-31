//! Contains x86_64-specific code to perform various relocation relaxation optimisations. These are
//! supposed to be optional for the linker to do, but it turns out that libc in some cases won't
//! work unless they're performed. e.g. it uses GOT relocations in _start, which cannot work in a
//! static-PIE binary because dynamic relocations haven't yet been applied to the GOT yet.

use crate::OutputKind;
use crate::elf::Elf64;
use crate::elf::PLT_ENTRY_SIZE;
use crate::elf::PropertyClass;
use crate::error;
use crate::error::Result;
use crate::malfunction_point_ret;
use crate::platform::Platform;
use crate::platform::PreviousRelocationInfo;
use crate::value_flags::ValueFlags;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::shf;
use linker_utils::elf::x86_64_rel_type_to_string;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::x86_64::RelaxationKind;
use linker_utils::x86_64::relocation_from_raw;
use object::elf::GNU_PROPERTY_UINT32_AND_HI;
use object::elf::GNU_PROPERTY_UINT32_AND_LO;
use object::elf::GNU_PROPERTY_UINT32_OR_HI;
use object::elf::GNU_PROPERTY_UINT32_OR_LO;
use object::elf::GNU_PROPERTY_X86_UINT32_AND_HI;
use object::elf::GNU_PROPERTY_X86_UINT32_AND_LO;
use object::elf::GNU_PROPERTY_X86_UINT32_OR_AND_HI;
use object::elf::GNU_PROPERTY_X86_UINT32_OR_AND_LO;
use object::elf::GNU_PROPERTY_X86_UINT32_OR_HI;
use object::elf::GNU_PROPERTY_X86_UINT32_OR_LO;

pub(crate) struct ElfX86_64;

const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
    0xf2, 0xff, 0x25, 0x0, 0x0, 0x0, 0x0, // bnd jmp *{relative GOT address}(%rip)
    0x0f, 0x1f, 0x44, 0x0, 0x0, // nopl   0x0(%rax,%rax,1)
];

const _ASSERTS: () = {
    assert!(PLT_ENTRY_TEMPLATE.len() as u64 == PLT_ENTRY_SIZE);
};

macro_rules! rel_info_from_type {
    ($r_type:expr) => {
        const { relocation_from_raw($r_type).unwrap() }
    };
}

impl crate::platform::Arch for ElfX86_64 {
    type Relaxation = Relaxation;
    type Platform = Elf64;

    fn arch_identifier() -> <Self::Platform as Platform>::ArchIdentifier {
        object::elf::EM_X86_64
    }

    #[inline(always)]
    fn relocation_from_raw(r_type: object::elf::RelocationType) -> Result<RelocationKindInfo> {
        linker_utils::x86_64::relocation_from_raw(r_type).ok_or_else(|| {
            error!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            )
        })
    }

    fn is_disallowed_for_interposable_symbols(r_type: object::elf::RelocationType) -> bool {
        matches!(
            r_type,
            object::elf::R_X86_64_32
                | object::elf::R_X86_64_32S
                | object::elf::R_X86_64_PC32
                | object::elf::R_X86_64_8
                | object::elf::R_X86_64_16
                | object::elf::R_X86_64_PC8
                | object::elf::R_X86_64_PC16
        )
    }

    fn is_disallowed_in_shared_object(r_type: object::elf::RelocationType) -> bool {
        matches!(
            r_type,
            object::elf::R_X86_64_32
                | object::elf::R_X86_64_32S
                | object::elf::R_X86_64_8
                | object::elf::R_X86_64_16
        )
    }

    fn get_dynamic_relocation_type(
        relocation: DynamicRelocationKind,
    ) -> object::elf::RelocationType {
        relocation.x86_64_r_type()
    }

    fn write_plt_entry(
        plt_entry: &mut [u8],
        got_address: u64,
        plt_address: u64,
    ) -> crate::error::Result {
        plt_entry.copy_from_slice(PLT_ENTRY_TEMPLATE);
        let offset: i32 = (got_address.wrapping_sub(plt_address + 0xb) as i64)
            .try_into()
            .map_err(|_| error!("PLT is more than 2GiB away from GOT"))?;
        plt_entry[7..11].copy_from_slice(&offset.to_le_bytes());
        Ok(())
    }

    fn rel_type_to_string(r_type: object::elf::RelocationType) -> std::borrow::Cow<'static, str> {
        x86_64_rel_type_to_string(r_type)
    }

    fn tp_offset_start(layout: &crate::layout::Layout<Elf64>) -> u64 {
        layout.tls_end_address()
    }

    fn get_property_class(property_type: u32) -> Option<crate::elf::PropertyClass> {
        match property_type {
            GNU_PROPERTY_X86_UINT32_AND_LO..=GNU_PROPERTY_X86_UINT32_AND_HI => {
                Some(PropertyClass::And)
            }
            GNU_PROPERTY_X86_UINT32_OR_LO..=GNU_PROPERTY_X86_UINT32_OR_HI => {
                Some(PropertyClass::Or)
            }
            GNU_PROPERTY_X86_UINT32_OR_AND_LO..=GNU_PROPERTY_X86_UINT32_OR_AND_HI => {
                Some(PropertyClass::AndOr)
            }
            GNU_PROPERTY_UINT32_AND_LO..=GNU_PROPERTY_UINT32_AND_HI => Some(PropertyClass::And),
            GNU_PROPERTY_UINT32_OR_LO..=GNU_PROPERTY_UINT32_OR_HI => Some(PropertyClass::Or),
            _ => None,
        }
    }

    fn merge_eflags(
        _eflags: impl Iterator<Item = object::elf::FileFlags>,
    ) -> Result<object::elf::FileFlags> {
        Ok(object::elf::FileFlags(0))
    }

    fn high_part_relocations() -> &'static [object::elf::RelocationType] {
        &[]
    }

    #[inline(always)]
    fn new_relaxation(
        relocation_kind: object::elf::RelocationType,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: SectionFlags,
        _relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
        _sym_addr: u64,
        _section_address: u64,
        _rel_addend: i64,
        _previous_relocation: Option<PreviousRelocationInfo<object::elf::RelocationType>>,
    ) -> Option<Self::Relaxation> {
        let is_known_address = flags.has_link_time_address();
        let is_absolute = flags.is_absolute() && !flags.is_dynamic();
        let is_absolute_address = is_known_address && output_kind.has_fixed_load_address();
        let interposable = flags.is_interposable();

        // IFuncs cannot be referenced directly. They always need to go via the GOT. So if we've got
        // say a PLT32 relocation, we don't want to relax it even if we're in a static executable.
        // Furthermore, if we encounter a relocation like PC32 to an ifunc, then we need to change
        // it so that it goes via the GOT. This is kind of the opposite of relaxation.
        if flags.is_ifunc() {
            return match relocation_kind {
                object::elf::R_X86_64_PC32 => {
                    return Some(Relaxation {
                        kind: RelaxationKind::NoOp,
                        rel_info: rel_info_from_type!(object::elf::R_X86_64_PLT32),
                        mandatory: true,
                    });
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

        match relocation_kind {
            object::elf::R_X86_64_REX_GOTPCRELX | object::elf::R_X86_64_CODE_4_GOTPCRELX
                if (relocation_kind == object::elf::R_X86_64_CODE_4_GOTPCRELX
                    && (offset >= 4 && section_bytes[offset - 4] == 0xd5))
                    || offset >= 3 =>
            {
                let b1 = section_bytes[offset - 2];
                let rex = section_bytes[offset - 3];

                // REX prefixed instruction with W=1, R=0/1, X=0, B=0
                if rex != 0x48 && rex != 0x4c {
                    return None;
                }

                if is_absolute || is_absolute_address {
                    let inst_offset = if relocation_kind == object::elf::R_X86_64_REX_GOTPCRELX {
                        3
                    } else {
                        4
                    };
                    match b1 {
                        // mov *x(%rip), reg
                        0x8b => {
                            return Some(Relaxation {
                                kind: RelaxationKind::RexMovIndirectToAbsolute(inst_offset),
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_32),
                                mandatory: output_kind.is_static_executable() && is_absolute,
                            });
                        }
                        // sub *x(%rip), reg
                        0x2b => {
                            return Some(Relaxation {
                                kind: RelaxationKind::RexSubIndirectToAbsolute(inst_offset),
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_32),
                                mandatory: output_kind.is_static_executable() && is_absolute,
                            });
                        }
                        // cmp *x(%rip), reg
                        0x3b => {
                            return Some(Relaxation {
                                kind: RelaxationKind::RexCmpIndirectToAbsolute(inst_offset),
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_32),
                                mandatory: output_kind.is_static_executable() && is_absolute,
                            });
                        }
                        _ => return None,
                    }
                } else if !interposable {
                    match b1 {
                        // mov *x(%rip), reg
                        0x8b => {
                            return Some(Relaxation {
                                kind: RelaxationKind::MovIndirectToLea,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_PC32),
                                mandatory: output_kind.is_static_executable(),
                            });
                        }
                        _ => return None,
                    }
                }
            }
            object::elf::R_X86_64_GOTPCRELX => {
                match section_bytes.get(offset - 2)? {
                    // mov *x(%rip), reg
                    0x8b => {
                        if is_absolute || is_absolute_address {
                            malfunction_point_ret!("no-mov-indirect-to-absolute", None);
                            return Some(Relaxation {
                                kind: RelaxationKind::MovIndirectToAbsolute,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_32),
                                mandatory: output_kind.is_static_executable(),
                            });
                        } else if !interposable {
                            return Some(Relaxation {
                                kind: RelaxationKind::MovIndirectToLea,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_PC32),
                                mandatory: output_kind.is_static_executable(),
                            });
                        }
                    }
                    _ => {}
                }
                if !interposable {
                    match section_bytes.get(offset - 2..offset)? {
                        // call *x(%rip)
                        [0xff, 0x15] => {
                            return Some(Relaxation {
                                kind: RelaxationKind::CallIndirectToRelative,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_PC32),
                                mandatory: output_kind.is_static_executable()
                                    && output_kind.is_position_independent(),
                            });
                        }
                        // jmp *x(%rip)
                        [0xff, 0x25] => {
                            malfunction_point_ret!("no-jmp-indirect-to-relative", None);
                            return Some(Relaxation {
                                kind: RelaxationKind::JmpIndirectToRelative,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_PC32),
                                mandatory: output_kind.is_static_executable()
                                    && output_kind.is_position_independent(),
                            });
                        }
                        _ => return None,
                    }
                }
                return None;
            }
            object::elf::R_X86_64_GOTPCREL if !interposable && offset >= 2 => {
                match section_bytes.get(offset - 2)? {
                    // mov *x(%rip), reg
                    0x8b => {
                        return Some(Relaxation {
                            kind: RelaxationKind::MovIndirectToLea,
                            rel_info: rel_info_from_type!(object::elf::R_X86_64_PC32),
                            mandatory: false,
                        });
                    }
                    _ => {}
                }
                return None;
            }
            object::elf::R_X86_64_GOTTPOFF | object::elf::R_X86_64_CODE_4_GOTTPOFF
                if output_kind.is_executable()
                    && !interposable
                    && ((relocation_kind == object::elf::R_X86_64_CODE_4_GOTTPOFF
                        && (offset >= 4 && section_bytes[offset - 4] == 0xd5))
                        || offset >= 3) =>
            {
                let inst_offset = if relocation_kind == object::elf::R_X86_64_GOTTPOFF {
                    3
                } else {
                    4
                };

                match section_bytes.get(offset - 3..offset - 1)? {
                    // mov *x(%rip), reg
                    [0x48 | 0x4c, 0x8b] => {
                        return Some(Relaxation {
                            kind: RelaxationKind::RexMovIndirectToAbsolute(inst_offset),
                            rel_info: rel_info_from_type!(object::elf::R_X86_64_TPOFF32),
                            mandatory: output_kind.is_static_executable(),
                        });
                    }
                    // add *x(%rip), reg1, reg2
                    [0x48 | 0x4c, 0x03] => {
                        return Some(Relaxation {
                            kind: RelaxationKind::RexAddIndirectToAbsolute(inst_offset),
                            rel_info: rel_info_from_type!(object::elf::R_X86_64_TPOFF32),
                            mandatory: false,
                        });
                    }
                    _ => {}
                }
            }
            object::elf::R_X86_64_CODE_6_GOTTPOFF
                if output_kind.is_executable() && !interposable && offset >= 6 =>
            {
                match section_bytes.get(offset - 6..offset - 1)? {
                    [0x62, l5, l4, l3, 0x1 | 0x3]
                        if (l5 & 0x47) == 0x44 && l4 & 0x87 == 0x84 && l3 & 0x14 != 0 =>
                    {
                        return Some(Relaxation {
                            kind: RelaxationKind::RexAddIndirectToAbsolute(6),
                            rel_info: rel_info_from_type!(object::elf::R_X86_64_TPOFF32),
                            mandatory: output_kind.is_static_executable(),
                        });
                    }
                    _ => {}
                }
            }
            object::elf::R_X86_64_PLT32 if !interposable => {
                return Some(Relaxation {
                    kind: RelaxationKind::NoOp,
                    rel_info: rel_info_from_type!(object::elf::R_X86_64_PC32),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_X86_64_PLTOFF64 if !interposable => {
                return Some(Relaxation {
                    kind: RelaxationKind::NoOp,
                    rel_info: rel_info_from_type!(object::elf::R_X86_64_GOTOFF64),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_X86_64_TLSGD if !interposable && output_kind.is_executable() => {
                let kind = match TlsGdForm::identify(section_bytes, offset)? {
                    TlsGdForm::Regular | TlsGdForm::RegularNoPlt => {
                        RelaxationKind::TlsGdToLocalExec
                    }
                    TlsGdForm::Large => RelaxationKind::TlsGdToLocalExecLarge,
                };
                return Some(Relaxation {
                    kind,
                    rel_info: rel_info_from_type!(object::elf::R_X86_64_TPOFF32),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_X86_64_TLSGD if output_kind.is_executable() => {
                let kind = match TlsGdForm::identify(section_bytes, offset)? {
                    TlsGdForm::Regular | TlsGdForm::RegularNoPlt => {
                        RelaxationKind::TlsGdToInitialExec
                    }
                    TlsGdForm::Large => {
                        // TODO
                        return None;
                    }
                };
                return Some(Relaxation {
                    kind,
                    rel_info: rel_info_from_type!(object::elf::R_X86_64_GOTTPOFF),
                    mandatory: false,
                });
            }
            object::elf::R_X86_64_TLSLD if output_kind.is_executable() => {
                // lea    0x0(%rip),%rdi
                if section_bytes.get(offset - 3..offset)? == [0x48, 0x8d, 0x3d] {
                    match section_bytes.get(offset + 4..offset + 6) {
                        // PC-relative direct call
                        Some(&[0xe8, _]) => {
                            return Some(Relaxation {
                                kind: RelaxationKind::TlsLdToLocalExec,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_NONE),
                                mandatory: output_kind.is_static_executable(),
                            });
                        }
                        Some(&[0x48, 0xb8]) => {
                            return Some(Relaxation {
                                kind: RelaxationKind::TlsLdToLocalExec64,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_NONE),
                                mandatory: false,
                            });
                        }
                        // PC-relative indirect call
                        Some(&[0xff, 0x15]) => {
                            return Some(Relaxation {
                                kind: RelaxationKind::TlsLdToLocalExecNoPlt,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_NONE),
                                mandatory: output_kind.is_static_executable(),
                            });
                        }
                        _ => {}
                    }
                }
            }
            object::elf::R_X86_64_GOTPC32_TLSDESC
            | object::elf::R_X86_64_CODE_4_GOTPC32_TLSDESC
                if !interposable
                    && output_kind.is_executable()
                    && ((relocation_kind == object::elf::R_X86_64_CODE_4_GOTPC32_TLSDESC
                        && (offset >= 4 && section_bytes[offset - 4] == 0xd5))
                        || offset >= 3) =>
            {
                // We require that the instruction that this relocation applies to is a LEA
                // instruction.
                let bytes = section_bytes.get(offset - 3..offset - 1);
                if bytes == Some(&[0x48, 0x8d]) || bytes == Some(&[0x4c, 0x8d]) {
                    return Some(Relaxation {
                        kind: RelaxationKind::TlsDescToLocalExec(
                            if relocation_kind == object::elf::R_X86_64_GOTPC32_TLSDESC {
                                3
                            } else {
                                4
                            },
                        ),
                        rel_info: rel_info_from_type!(object::elf::R_X86_64_TPOFF32),
                        mandatory: output_kind.is_static_executable(),
                    });
                }
            }
            // Note, the conditions on this relaxation (is_executable) must match those on
            // TLSDESC_CALL below.
            object::elf::R_X86_64_GOTPC32_TLSDESC if output_kind.is_executable() => {
                // We require that the instruction that this relocation applies to is a LEA
                // instruction.
                let bytes = section_bytes.get(offset - 3..offset - 1);
                if bytes == Some(&[0x48, 0x8d]) || bytes == Some(&[0x4c, 0x8d]) {
                    return Some(Relaxation {
                        kind: RelaxationKind::TlsDescToInitialExec,
                        rel_info: rel_info_from_type!(object::elf::R_X86_64_GOTTPOFF),
                        mandatory: output_kind.is_static_executable(),
                    });
                }
            }
            // Note, the conditions on this relaxation (is_executable) must match those on
            // GOTPC32_TLSDESC above.
            object::elf::R_X86_64_TLSDESC_CALL if output_kind.is_executable() => {
                return Some(Relaxation {
                    kind: RelaxationKind::SkipTlsDescCall,
                    rel_info: rel_info_from_type!(object::elf::R_X86_64_NONE),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            _ => return None,
        }
        None
    }

    fn get_source_info<'data>(
        object: &<Self::Platform as Platform>::File<'data>,
        relocations: &<Self::Platform as Platform>::RelocationSections,
        section: &<Self::Platform as Platform>::SectionHeader,
        offset_in_section: u64,
    ) -> Result<crate::platform::SourceInfo> {
        crate::dwarf_address_info::get_source_info::<crate::elf::Class64, Self>(
            object,
            relocations,
            section,
            offset_in_section,
        )
    }

    fn fill_nop_padding(buf: &mut [u8]) {
        buf.fill(0xcc);
    }

    fn fill_section_padding(buf: &mut [u8], section_flags: object::elf::SectionFlags) {
        if section_flags.contains(object::elf::SHF_EXECINSTR) {
            Self::fill_nop_padding(buf);
        } else {
            buf.fill(0);
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
    mandatory: bool,
}

impl crate::platform::Relaxation for Relaxation {
    fn apply(&self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64) {
        self.kind.apply(section_bytes, offset_in_section, addend);
    }

    fn rel_info(&self) -> RelocationKindInfo {
        self.rel_info
    }

    fn debug_kind(&self) -> impl std::fmt::Debug {
        &self.kind
    }

    fn next_modifier(&self) -> RelocationModifier {
        self.kind.next_modifier()
    }

    fn is_mandatory(&self) -> bool {
        self.mandatory
    }
}

enum TlsGdForm {
    Regular,
    Large,
    RegularNoPlt,
}

impl TlsGdForm {
    fn identify(bytes: &[u8], offset: usize) -> Option<Self> {
        // data16 lea 0x0(%rip),%rdi
        // data16 data16 rex.W call {relative function offset}
        if bytes.get(offset - 4..offset) == Some(&[0x66, 0x48, 0x8d, 0x3d])
            && bytes.get(offset + 4..offset + 8) == Some(&[0x66, 0x66, 0x48, 0xe8])
        {
            return Some(Self::Regular);
        }

        // data16 lea 0x0(%rip),%rdi
        // data16 rex.W call *__tls_get_addr@GOTPCREL(%rip)
        if bytes.get(offset - 4..offset) == Some(&[0x66, 0x48, 0x8d, 0x3d])
            && bytes.get(offset + 4..offset + 8) == Some(&[0x66, 0x48, 0xff, 0x15])
        {
            return Some(Self::RegularNoPlt);
        }

        // lea 0x0(%rip),%rdi
        // movabs $X,%rax
        // add %rbx,%rax
        // call *%rax
        if bytes.get(offset - 3..offset) == Some(&[0x48, 0x8d, 0x3d])
            && bytes.get(offset + 4..offset + 6) == Some(&[0x48, 0xb8])
            && bytes.get(offset + 14..offset + 19) == Some(&[0x48, 0x01, 0xd8, 0xff, 0xd0])
        {
            malfunction_point_ret!("no-identify-tls-gd-large", None);
            return Some(Self::Large);
        }

        None
    }
}

#[test]
fn test_relaxation() {
    use crate::args::RelocationModel;
    use crate::platform::Arch as _;
    use crate::platform::Relaxation as _;

    #[track_caller]
    fn check(
        relocation_kind: object::elf::RelocationType,
        bytes_in: &[u8],
        address: &[u8],
        absolute: &[u8],
    ) {
        let mut out = bytes_in.to_owned();
        let mut offset = bytes_in.len() as u64;
        if let Some(r) = ElfX86_64::new_relaxation(
            relocation_kind,
            bytes_in,
            offset,
            ValueFlags::empty(),
            OutputKind::StaticExecutable(RelocationModel::PositionIndependent),
            shf::EXECINSTR,
            None,
            0,
            0,
            0,
            None,
        ) {
            r.apply(&mut out, &mut offset, &mut 0);

            assert_eq!(
                out, address,
                "resolved: Expected {address:x?}, got {out:x?}"
            );
        }
        if let Some(r) = ElfX86_64::new_relaxation(
            relocation_kind,
            bytes_in,
            offset,
            ValueFlags::ABSOLUTE,
            OutputKind::StaticExecutable(RelocationModel::PositionIndependent),
            shf::EXECINSTR,
            None,
            0,
            0,
            0,
            None,
        ) {
            out.copy_from_slice(bytes_in);
            r.apply(&mut out, &mut offset, &mut 0);
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
