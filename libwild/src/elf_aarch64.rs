use crate::elf::PLT_ENTRY_SIZE;
use crate::elf::PropertyClass;
use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::layout::Layout;
use crate::platform::ObjectFile as _;
use linker_utils::aarch64::RelaxationKind;
use linker_utils::aarch64::relocation_type_from_raw;
use linker_utils::elf::AArch64Instruction;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::PAGE_MASK_4KB;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::SIZE_4KB;
use linker_utils::elf::aarch64_rel_type_to_string;
use linker_utils::elf::shf;
use linker_utils::relaxation::RelocationModifier;
use object::elf::GNU_PROPERTY_AARCH64_FEATURE_1_AND;

pub(crate) struct ElfAArch64;

const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0x10, 0x00, 0x00, 0x90, // adrp x16, page(&(.got.plt[n]))
    0x11, 0x02, 0x40, 0xf9, // ldr x17, [x16, offset(&(.got.plt[n]))]
    0x20, 0x02, 0x1f, 0xd6, // br x17
    0x1f, 0x20, 0x03, 0xd5, // nop
];

const _ASSERTS: () = {
    assert!(PLT_ENTRY_TEMPLATE.len() as u64 == PLT_ENTRY_SIZE);
};

macro_rules! rel_info_from_type {
    ($r_type:expr) => {
        const { relocation_type_from_raw($r_type).unwrap() }
    };
}

impl<'data> crate::platform::Platform<'data> for ElfAArch64 {
    type Relaxation = Relaxation;
    type File = crate::elf::File<'data>;

    fn elf_header_arch_magic() -> u16 {
        object::elf::EM_AARCH64
    }

    // The table of the relocations is documented here:
    // https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst.
    #[inline(always)]
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        linker_utils::aarch64::relocation_type_from_raw(r_type).ok_or_else(|| {
            error!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            )
        })
    }

    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32 {
        relocation.aarch64_r_type()
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        aarch64_rel_type_to_string(r_type)
    }

    fn write_plt_entry(
        plt_entry: &mut [u8],
        got_address: u64,
        plt_address: u64,
    ) -> crate::error::Result {
        // TODO: For simplicity, we assume now the PLT entry precedes the GOT entry, so we can
        // make the offset calculation in the unsigned type.
        debug_assert!(plt_address < got_address);

        plt_entry.copy_from_slice(PLT_ENTRY_TEMPLATE);
        let plt_page_address = plt_address & !PAGE_MASK_4KB;
        let offset = got_address.wrapping_sub(plt_page_address);
        ensure!(offset < (1 << 32), "PLT is more than 4GiB away from GOT");
        AArch64Instruction::Adr.write_to_value(
            // The immediate value represents a distance in pages.
            offset / SIZE_4KB,
            false,
            &mut plt_entry[0..4],
        );
        AArch64Instruction::LdrRegister.write_to_value(
            // The immediate offset is scaled by 8 as we are loading 8 bytes.
            (offset & PAGE_MASK_4KB) / 8,
            false,
            &mut plt_entry[4..8],
        );
        Ok(())
    }

    fn local_symbols_in_debug_info() -> bool {
        false
    }

    fn tp_offset_start(layout: &Layout<'_>) -> u64 {
        layout.tls_start_address_aarch64()
    }

    fn get_property_class(property_type: u32) -> Option<PropertyClass> {
        match property_type {
            GNU_PROPERTY_AARCH64_FEATURE_1_AND => Some(PropertyClass::And),
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
        flags: crate::value_flags::ValueFlags,
        output_kind: crate::output_kind::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
        non_zero_address: bool,
        _relax_deltas: Option<&linker_utils::relaxation::SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation>
    where
        Self: std::marker::Sized,
    {
        let mut relocation = ElfAArch64::relocation_from_raw(relocation_kind).unwrap();
        let interposable = flags.is_interposable();

        // IFuncs cannot be referenced directly, they always need to go via the GOT.
        if flags.is_ifunc() {
            return match relocation_kind {
                object::elf::R_AARCH64_CALL26 | object::elf::R_AARCH64_JUMP26 => {
                    relocation.kind = RelocationKind::PltRelative;
                    return Some(Relaxation {
                        kind: RelaxationKind::NoOp,
                        rel_info: relocation,
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
            object::elf::R_AARCH64_CALL26 | object::elf::R_AARCH64_JUMP26 if !interposable => {
                return if non_zero_address {
                    relocation.kind = RelocationKind::Relative;
                    Some(Relaxation {
                        kind: RelaxationKind::NoOp,
                        rel_info: relocation,
                        mandatory: output_kind.is_static_executable(),
                    })
                } else {
                    // GNU ld replaces: 'bl 0' with 'nop'
                    Some(Relaxation {
                        kind: RelaxationKind::ReplaceWithNop,
                        rel_info: rel_info_from_type!(object::elf::R_AARCH64_NONE),
                        mandatory: output_kind.is_static_executable(),
                    })
                };
            }

            // Relax TLSDESC to local exec
            object::elf::R_AARCH64_TLSDESC_ADR_PAGE21
                if output_kind.is_executable() && !interposable =>
            {
                debug_assert!(
                    section_bytes[offset..].starts_with(TLSDESC_ADR_PAGE21_INSN_SEQUENCE),
                    "Unknown R_AARCH64_TLSDESC_ADR_PAGE21 instruction"
                );
                return Some(Relaxation {
                    kind: RelaxationKind::ReplaceWithNop,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_NONE),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_LD64_LO12
                if output_kind.is_executable() && !interposable =>
            {
                return Some(Relaxation {
                    kind: RelaxationKind::ReplaceWithNop,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_NONE),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_ADD_LO12
                if output_kind.is_executable() && !interposable =>
            {
                debug_assert!(
                    section_bytes[offset..].starts_with(TLSDESC_ADD_LO12_INSN_SEQUENCE),
                    "Unknown R_AARCH64_TLSDESC_ADD_LO12 instruction"
                );
                return Some(Relaxation {
                    kind: RelaxationKind::MovzX0Lsl16,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_CALL if output_kind.is_executable() && !interposable => {
                return Some(Relaxation {
                    kind: RelaxationKind::MovkX0,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC),
                    mandatory: output_kind.is_static_executable(),
                });
            }

            // Relax TLSDESC to initial exec
            object::elf::R_AARCH64_TLSDESC_ADR_PAGE21 if output_kind.is_executable() => {
                debug_assert!(
                    section_bytes[offset..].starts_with(TLSDESC_ADR_PAGE21_INSN_SEQUENCE),
                    "Unknown R_AARCH64_TLSDESC_ADR_PAGE21 instruction"
                );
                return Some(Relaxation {
                    kind: RelaxationKind::ReplaceWithNop,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_NONE),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_LD64_LO12 if output_kind.is_executable() => {
                return Some(Relaxation {
                    kind: RelaxationKind::ReplaceWithNop,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_NONE),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_ADD_LO12 if output_kind.is_executable() => {
                debug_assert!(
                    section_bytes[offset..].starts_with(TLSDESC_ADD_LO12_INSN_SEQUENCE),
                    "Unknown R_AARCH64_TLSDESC_ADD_LO12 instruction"
                );
                return Some(Relaxation {
                    kind: RelaxationKind::AdrpX0,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21),
                    mandatory: output_kind.is_static_executable(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_CALL if output_kind.is_executable() => {
                return Some(Relaxation {
                    kind: RelaxationKind::LdrX0,
                    rel_info: rel_info_from_type!(
                        object::elf::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
                    ),
                    mandatory: output_kind.is_static_executable(),
                });
            }

            // Relax local exec to init exec
            object::elf::R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21
                if output_kind.is_executable() && !interposable =>
            {
                return Some(Relaxation {
                    kind: RelaxationKind::MovzXnLsl16,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1),
                    mandatory: false,
                });
            }
            object::elf::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC
                if output_kind.is_executable() && !interposable =>
            {
                return Some(Relaxation {
                    kind: RelaxationKind::MovkXn,
                    rel_info: rel_info_from_type!(object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC),
                    mandatory: false,
                });
            }

            _ => (),
        }

        None
    }

    fn is_symbol_variant_pcs(object: &Self::File, symbol_index: object::SymbolIndex) -> bool {
        object
            .symbol(symbol_index)
            .is_ok_and(|sym| (sym.st_other & object::elf::STO_AARCH64_VARIANT_PCS) != 0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
    mandatory: bool,
}

const TLSDESC_ADR_PAGE21_INSN_SEQUENCE: &[u8] = &[
    0x0, 0x0, 0x0, 0x90, // adrp    x0, 0
];

const TLSDESC_ADD_LO12_INSN_SEQUENCE: &[u8] = &[
    0x0, 0x0, 0x0, 0x91, // add     x0, x0, #0x0
];

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
