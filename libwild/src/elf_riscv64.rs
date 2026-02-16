use crate::elf::PLT_ENTRY_SIZE;
use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::platform::Platform;
use itertools::Itertools;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RISCV_TLS_DTV_OFFSET;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RiscVInstruction;
use linker_utils::elf::riscv64_rel_type_to_string;
use linker_utils::elf::shf;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::riscv64::RelaxationKind;
use linker_utils::riscv64::relocation_type_from_raw;
use object::elf::EF_RISCV_FLOAT_ABI;
use object::elf::EF_RISCV_RV64ILP32;
use object::elf::EF_RISCV_RVE;

pub(crate) struct ElfRiscV64;

const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0x17, 0x0e, 0x0, 0x0, // auipc t3,offset_high(&(.got.plt[n])
    0x03, 0x3e, 0x0e, 0x0, // ld t3,offset_low(&(.got.plt[n])(t3)
    0x67, 0x03, 0x0e, 0x0, // jalr t1,t3
    0x73, 0x0, 0x10, 0x0, // ebreak
];

const _ASSERTS: () = {
    assert!(PLT_ENTRY_TEMPLATE.len() as u64 == PLT_ENTRY_SIZE);
};

impl crate::platform::Platform for ElfRiscV64 {
    type Relaxation = Relaxation;
    type Format = crate::elf::Elf;

    const KIND: crate::arch::Architecture = crate::arch::Architecture::RISCV64;

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
        RISCV_TLS_DTV_OFFSET
    }

    fn local_symbols_in_debug_info() -> bool {
        true
    }

    fn tp_offset_start(layout: &crate::layout::Layout) -> u64 {
        layout.tls_start_address()
    }

    fn get_property_class(_property_type: u32) -> Option<crate::elf::PropertyClass> {
        None
    }

    // Allow the lint for `exactly_one`.
    // Tracking issue available at: https://github.com/rust-lang/rust/issues/149266
    #[allow(unstable_name_collisions)]
    fn merge_eflags(eflags: impl Iterator<Item = u32>) -> Result<u32> {
        let eflags = eflags.collect_vec();
        let or_eflags = eflags.iter().fold(0, |acc, x| acc | x);
        ensure!(
            eflags
                .iter()
                .map(|flag| flag & EF_RISCV_FLOAT_ABI)
                .unique()
                .exactly_one()
                .is_ok(),
            "Float ABI flag mismatch"
        );
        ensure!(
            eflags
                .iter()
                .map(|flag| flag & EF_RISCV_RVE)
                .unique()
                .exactly_one()
                .is_ok(),
            "RVE flag mismatch"
        );
        ensure!(
            eflags
                .iter()
                .map(|flag| flag & EF_RISCV_RV64ILP32)
                .unique()
                .exactly_one()
                .is_ok(),
            "RV64ILP32 flag mismatch"
        );

        Ok(or_eflags)
    }

    fn high_part_relocations() -> &'static [u32] {
        &[
            object::elf::R_RISCV_HI20,
            object::elf::R_RISCV_PCREL_HI20,
            object::elf::R_RISCV_GOT_HI20,
            object::elf::R_RISCV_TLS_GOT_HI20,
            object::elf::R_RISCV_TLS_GD_HI20,
            object::elf::R_RISCV_TPREL_HI20,
        ]
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
    mandatory: bool,
}

macro_rules! rel_info_from_type {
    ($r_type:expr) => {
        const { relocation_type_from_raw($r_type).unwrap() }
    };
}

impl crate::platform::Relaxation for Relaxation {
    #[allow(unused_variables)]
    #[inline(always)]
    fn new(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: crate::value_flags::ValueFlags,
        output_kind: crate::output_kind::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
        non_zero_address: bool,
    ) -> Option<Self>
    where
        Self: std::marker::Sized,
    {
        let mut relocation = ElfRiscV64::relocation_from_raw(relocation_kind).unwrap();
        let interposable = flags.is_interposable();

        // All relaxations below only apply to executable code, so we shouldn't attempt them if a
        // relocation is in a non-executable section.
        if !section_flags.contains(shf::EXECINSTR) {
            return None;
        }

        let offset = offset_in_section as usize;

        match relocation_kind {
            object::elf::R_RISCV_CALL | object::elf::R_RISCV_CALL_PLT if !interposable => {
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
                        rel_info: rel_info_from_type!(object::elf::R_RISCV_NONE),
                        mandatory: output_kind.is_static_executable(),
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

    fn is_mandatory(&self) -> bool {
        self.mandatory
    }
}
