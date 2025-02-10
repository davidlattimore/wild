use crate::arch::Arch;
use crate::elf::DEFAULT_AARCH64_PAGE_IGNORED_MASK;
use crate::elf::DEFAULT_AARCH64_PAGE_MASK;
use crate::elf::DEFAULT_AARCH64_PAGE_SIZE;
use crate::elf::PLT_ENTRY_SIZE;
use crate::resolution::ValueFlags;
use anyhow::anyhow;
use anyhow::Result;
use linker_utils::aarch64::relocation_type_from_raw;
use linker_utils::aarch64::RelaxationKind;
use linker_utils::elf::aarch64_rel_type_to_string;
use linker_utils::elf::shf;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationInstruction;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;

pub(crate) struct AArch64;

const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0x10, 0x00, 0x00, 0x90, // adrp x16, page(&(.got.plt[n]))
    0x11, 0x02, 0x40, 0xf9, // ldr x17, [x16, offset(&(.got.plt[n]))]
    0x20, 0x02, 0x1f, 0xd6, // br x17
    0x1f, 0x20, 0x03, 0xd5, // nop
];

const _ASSERTS: () = {
    assert!(PLT_ENTRY_TEMPLATE.len() as u64 == PLT_ENTRY_SIZE);
};

impl crate::arch::Arch for AArch64 {
    type Relaxation = Relaxation;

    fn elf_header_arch_magic() -> u16 {
        object::elf::EM_AARCH64
    }

    // The table of the relocations is documented here:
    // https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst.
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        linker_utils::aarch64::relocation_type_from_raw(r_type).ok_or_else(|| {
            anyhow!(
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
        let plt_page_address = plt_address & DEFAULT_AARCH64_PAGE_IGNORED_MASK;
        let offset = got_address.wrapping_sub(plt_page_address);
        anyhow::ensure!(offset < (1 << 32), "PLT is more than 4GiB away from GOT");
        RelocationInstruction::Adr.write_to_value(
            // The immediate value represents a distance in pages.
            offset / DEFAULT_AARCH64_PAGE_SIZE,
            false,
            &mut plt_entry[0..4],
        );
        RelocationInstruction::LdrRegister.write_to_value(
            // The immediate offset is scaled by 8 as we are loading 8 bytes.
            (offset & DEFAULT_AARCH64_PAGE_MASK) / 8,
            false,
            &mut plt_entry[4..8],
        );
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
}

impl crate::arch::Relaxation for Relaxation {
    #[allow(unused_variables)]
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        value_flags: crate::resolution::ValueFlags,
        output_kind: crate::args::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
    ) -> Option<Self>
    where
        Self: std::marker::Sized,
    {
        let mut relocation = AArch64::relocation_from_raw(relocation_kind).unwrap();
        let can_bypass_got = value_flags.contains(ValueFlags::CAN_BYPASS_GOT);

        // IFuncs cannot be referenced directly, they always need to go via the GOT.
        if value_flags.contains(ValueFlags::IFUNC) {
            return match relocation_kind {
                object::elf::R_AARCH64_CALL26 | object::elf::R_AARCH64_JUMP26 => {
                    relocation.kind = RelocationKind::PltRelative;
                    return Some(Relaxation {
                        kind: RelaxationKind::NoOp,
                        rel_info: relocation,
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
        // TODO: Try fetching the symbol kind lazily. For most relocation, we don't need it, but
        // because fetching it contains potential error paths, the optimiser probably can't optimise
        // away fetching it.

        match relocation_kind {
            object::elf::R_AARCH64_CALL26 | object::elf::R_AARCH64_JUMP26 if can_bypass_got => {
                relocation.kind = RelocationKind::Relative;
                return Some(Relaxation {
                    kind: RelaxationKind::NoOp,
                    rel_info: relocation,
                });
            }

            object::elf::R_AARCH64_TLSDESC_ADR_PAGE21 if can_bypass_got => {
                // TODO: check we met all consecutive 4 instructions!
                return Some(Relaxation {
                    kind: RelaxationKind::ReplaceWithNop,
                    rel_info: relocation_type_from_raw(object::elf::R_AARCH64_NONE).unwrap(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_LD64_LO12 if can_bypass_got => {
                return Some(Relaxation {
                    kind: RelaxationKind::ReplaceWithNop,
                    rel_info: relocation_type_from_raw(object::elf::R_AARCH64_NONE).unwrap(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_ADD_LO12 if can_bypass_got => {
                return Some(Relaxation {
                    kind: RelaxationKind::MovzX0Lsl16,
                    rel_info: relocation_type_from_raw(object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1)
                        .unwrap(),
                });
            }
            object::elf::R_AARCH64_TLSDESC_CALL if can_bypass_got => {
                return Some(Relaxation {
                    kind: RelaxationKind::MovkX0,
                    rel_info: relocation_type_from_raw(
                        object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC,
                    )
                    .unwrap(),
                });
            }
            object::elf::R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 if can_bypass_got => {
                return Some(Relaxation {
                    kind: RelaxationKind::MovzXnLsl16,
                    rel_info: relocation_type_from_raw(object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1)
                        .unwrap(),
                });
            }
            object::elf::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC if can_bypass_got => {
                return Some(Relaxation {
                    kind: RelaxationKind::MovkXn,
                    rel_info: relocation_type_from_raw(
                        object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC,
                    )
                    .unwrap(),
                });
            }

            _ => (),
        }

        None
    }

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
}
