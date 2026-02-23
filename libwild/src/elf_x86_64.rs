//! Contains x86_64-specific code to perform various relocation relaxation optimisations. These are
//! supposed to be optional for the linker to do, but it turns out that libc in some cases won't
//! work unless they're performed. e.g. it uses GOT relocations in _start, which cannot work in a
//! static-PIE binary because dynamic relocations haven't yet been applied to the GOT yet.

use crate::OutputKind;
use crate::elf::PLT_ENTRY_SIZE;
use crate::elf::PropertyClass;
use crate::error;
use crate::error::Result;
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

impl<'data> crate::platform::Platform<'data> for ElfX86_64 {
    type Relaxation = Relaxation;
    type File = crate::elf::File<'data>;

    const KIND: crate::arch::Architecture = crate::arch::Architecture::X86_64;

    fn elf_header_arch_magic() -> u16 {
        object::elf::EM_X86_64
    }

    #[inline(always)]
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        linker_utils::x86_64::relocation_from_raw(r_type).ok_or_else(|| {
            error!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            )
        })
    }

    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32 {
        relocation.x86_64_r_type()
    }

    fn write_plt_entry(
        plt_entry: &mut [u8],
        got_address: u64,
        plt_address: u64,
    ) -> crate::error::Result {
        plt_entry.copy_from_slice(PLT_ENTRY_TEMPLATE);
        let offset: i32 = ((got_address.wrapping_sub(plt_address + 0xb)) as i64)
            .try_into()
            .map_err(|_| error!("PLT is more than 2GiB away from GOT"))?;
        plt_entry[7..11].copy_from_slice(&offset.to_le_bytes());
        Ok(())
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        x86_64_rel_type_to_string(r_type)
    }

    fn local_symbols_in_debug_info() -> bool {
        false
    }

    fn tp_offset_start(layout: &crate::layout::Layout<'data>) -> u64 {
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

    fn merge_eflags(_eflags: impl Iterator<Item = u32>) -> Result<u32> {
        Ok(0)
    }

    fn high_part_relocations() -> &'static [u32] {
        &[]
    }

    #[inline(always)]
    fn new_relaxation(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: ValueFlags,
        output_kind: OutputKind,
        section_flags: SectionFlags,
        _non_zero_address: bool,
        _relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation> {
        let is_known_address = flags.is_address();
        let is_absolute = flags.is_absolute() && !flags.is_dynamic();
        let non_relocatable = !output_kind.is_relocatable();
        let is_absolute_address = is_known_address && non_relocatable;
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
            object::elf::R_X86_64_REX_GOTPCRELX => {
                if offset < 3 {
                    return None;
                }
                let b1 = section_bytes[offset - 2];
                let rex = section_bytes[offset - 3];

                // REX prefixed instruction with W=1, R=0/1, X=0, B=0
                if rex != 0x48 && rex != 0x4c {
                    return None;
                }

                if is_absolute || is_absolute_address {
                    match b1 {
                        // mov *x(%rip), reg
                        0x8b => {
                            return Some(Relaxation {
                                kind: RelaxationKind::RexMovIndirectToAbsolute,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_32),
                                mandatory: output_kind.is_static_executable(),
                            });
                        }
                        // sub *x(%rip), reg
                        0x2b => {
                            return Some(Relaxation {
                                kind: RelaxationKind::RexSubIndirectToAbsolute,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_32),
                                mandatory: output_kind.is_static_executable(),
                            });
                        }
                        // cmp *x(%rip), reg
                        0x3b => {
                            return Some(Relaxation {
                                kind: RelaxationKind::RexCmpIndirectToAbsolute,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_32),
                                mandatory: output_kind.is_static_executable(),
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
                                mandatory: output_kind.is_static_executable(),
                            });
                        }
                        // jmp *x(%rip)
                        [0xff, 0x25] => {
                            return Some(Relaxation {
                                kind: RelaxationKind::JmpIndirectToRelative,
                                rel_info: rel_info_from_type!(object::elf::R_X86_64_PC32),
                                mandatory: output_kind.is_static_executable(),
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
            object::elf::R_X86_64_GOTTPOFF if output_kind.is_executable() && !interposable => {
                match section_bytes.get(offset - 3..offset - 1)? {
                    // mov *x(%rip), reg
                    [0x48 | 0x4c, 0x8b] => {
                        return Some(Relaxation {
                            kind: RelaxationKind::RexMovIndirectToAbsolute,
                            rel_info: rel_info_from_type!(object::elf::R_X86_64_TPOFF32),
                            mandatory: false,
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
                    TlsGdForm::Regular => RelaxationKind::TlsGdToLocalExec,
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
                    TlsGdForm::Regular => RelaxationKind::TlsGdToInitialExec,
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
                                mandatory: false,
                            });
                        }
                        // TODO: Make a test for this. Also, the description of TlsLdToLocalExec64
                        // possibly doesn't match what we're actually checking here.
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
                                mandatory: false,
                            });
                        }
                        _ => {}
                    }
                }
            }
            object::elf::R_X86_64_GOTPC32_TLSDESC
                if !interposable && output_kind.is_executable() =>
            {
                // We require that the instruction that this relocation applies to is a LEA
                // instruction.
                let bytes = section_bytes.get(offset - 3..offset - 1);
                if bytes == Some(&[0x48, 0x8d]) || bytes == Some(&[0x4c, 0x8d]) {
                    return Some(Relaxation {
                        kind: RelaxationKind::TlsDescToLocalExec,
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
        };
        None
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

        // lea 0x0(%rip),%rdi
        // movabs $X,%rax
        // TODO: This branch is not currently exercised by our tests. Add a test and document the
        // third instruction.
        if bytes.get(offset - 3..offset) == Some(&[0x48, 0x8d, 0x3d])
            && bytes.get(offset + 4..offset + 6) == Some(&[0x48, 0xb8])
            && bytes.get(offset + 14..offset + 19) == Some(&[0x48, 0x01, 0xd8, 0xff, 0xd0])
        {
            return Some(Self::Large);
        }

        None
    }
}

#[test]
fn test_relaxation() {
    use crate::args::RelocationModel;
    use crate::platform::Platform as _;
    use crate::platform::Relaxation as _;

    #[track_caller]
    fn check(relocation_kind: u32, bytes_in: &[u8], address: &[u8], absolute: &[u8]) {
        let mut out = bytes_in.to_owned();
        let mut offset = bytes_in.len() as u64;
        if let Some(r) = ElfX86_64::new_relaxation(
            relocation_kind,
            bytes_in,
            offset,
            ValueFlags::empty(),
            OutputKind::StaticExecutable(RelocationModel::Relocatable),
            shf::EXECINSTR,
            true,
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
            OutputKind::StaticExecutable(RelocationModel::Relocatable),
            shf::EXECINSTR,
            true,
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
