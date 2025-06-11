use crate::arch::Arch;
use crate::arch::TcbPlacement;
use crate::elf::PLT_ENTRY_SIZE;
use crate::error;
use crate::error::Result;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RiscVInstruction;
use linker_utils::elf::riscv64_rel_type_to_string;
use linker_utils::elf::shf;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::riscv64::RelaxationKind;
use linker_utils::riscv64::relocation_type_from_raw;

pub(crate) struct RiscV64;

const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0x17, 0x0e, 0x0, 0x0, // auipc t3,offset_high(&(.got.plt[n])
    0x03, 0x3e, 0x0e, 0x0, // ld t3,offset_low(&(.got.plt[n])(t3)
    0x67, 0x03, 0x0e, 0x0, // jalr t1,t3
    0x73, 0x0, 0x10, 0x0, // ebreak
];

const _ASSERTS: () = {
    assert!(PLT_ENTRY_TEMPLATE.len() as u64 == PLT_ENTRY_SIZE);
};

impl crate::arch::Arch for RiscV64 {
    type Relaxation = Relaxation;

    fn elf_header_arch_magic() -> u16 {
        object::elf::EM_RISCV
    }

    #[inline(always)]
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        linker_utils::riscv64::relocation_type_from_raw(r_type).ok_or_else(|| {
            error!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            )
        })
    }

    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32 {
        relocation.riscv64_r_type()
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        riscv64_rel_type_to_string(r_type)
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
        RiscVInstruction::UiType.write_to_value(
            got_address.wrapping_sub(plt_address),
            false,
            &mut plt_entry[0..8],
        );
        Ok(())
    }

    fn get_dtv_offset() -> u64 {
        0x800
    }

    fn local_symbols_in_debug_info() -> bool {
        true
    }

    fn tcb_placement() -> TcbPlacement {
        TcbPlacement::AfterTp
    }

    fn tp_offset_start(layout: &crate::layout::Layout) -> u64 {
        layout.tls_start_address()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
}

impl crate::arch::Relaxation for Relaxation {
    #[allow(unused_variables)]
    #[inline(always)]
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        value_flags: crate::resolution::ValueFlags,
        output_kind: crate::args::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
        non_zero_address: bool,
    ) -> Option<Self>
    where
        Self: std::marker::Sized,
    {
        let mut relocation = RiscV64::relocation_from_raw(relocation_kind).unwrap();
        let interposable = value_flags.is_interposable();

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
            object::elf::R_RISCV_CALL | object::elf::R_RISCV_CALL_PLT if !interposable => {
                return if non_zero_address {
                    relocation.kind = RelocationKind::Relative;
                    Some(Relaxation {
                        kind: RelaxationKind::NoOp,
                        rel_info: relocation,
                    })
                } else {
                    // GNU ld replaces: 'bl 0' with 'nop'
                    Some(Relaxation {
                        kind: RelaxationKind::ReplaceWithNop,
                        rel_info: relocation_type_from_raw(object::elf::R_RISCV_NONE).unwrap(),
                    })
                };
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
