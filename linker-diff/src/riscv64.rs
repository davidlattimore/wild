use crate::ArchKind;
use crate::arch::Arch;
use crate::arch::Instruction;
use crate::arch::Relaxation;
use crate::arch::RelaxationByteRange;
use crate::asm_diff::BasicValueKind;
use crate::utils::decode_insn_with_objdump;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::riscv64_rel_type_to_string;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::riscv64::RelaxationKind;
use linker_utils::utils::u32_from_slice;
use std::fmt::Display;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RiscV64;

impl Arch for RiscV64 {
    type RType = RType;

    type RelaxationKind = RelaxationKind;

    type RawInstruction = Option<String>;

    const MAX_RELAX_MODIFY_BEFORE: u64 = 0;
    const MAX_RELAX_MODIFY_AFTER: u64 = 4;

    fn possible_relaxations_do(
        _r_type: Self::RType,
        _section_kind: object::SectionKind,
        _cb: impl FnMut(crate::arch::Relaxation<Self>),
    ) {
        // TODO: Implement relaxation for RISC-V
    }

    fn relaxation_byte_range(_relaxation: Relaxation<Self>) -> RelaxationByteRange {
        RelaxationByteRange {
            offset_shift: 0,
            num_bytes: 4,
        }
    }

    fn apply_relaxation(
        relaxation_kind: Self::RelaxationKind,
        section_bytes: &mut [u8],
        offset_in_section: &mut u64,
        addend: &mut i64,
    ) {
        relaxation_kind.apply(section_bytes, offset_in_section, addend);
    }

    fn next_relocation_modifier(relaxation_kind: Self::RelaxationKind) -> RelocationModifier {
        relaxation_kind.next_modifier()
    }

    fn instruction_to_string(instruction: &Instruction<Self>) -> String {
        if let Some(str) = instruction.raw_instruction.as_ref() {
            return str.to_owned();
        }
        String::new()
    }

    fn decode_instructions_in_range(
        section_bytes: &[u8],
        section_address: u64,
        _function_offset_in_section: u64,
        range: std::ops::Range<u64>,
    ) -> Vec<crate::arch::Instruction<'_, Self>> {
        let mut offset = range.start & !3;

        let mut instructions = Vec::new();

        while offset < range.end {
            if offset as usize + 4 > section_bytes.len() {
                break;
            }
            let bytes = &section_bytes[offset as usize..offset as usize + 4];
            let address = section_address + offset;

            let raw_instruction = decode_insn_with_objdump(bytes, address, ArchKind::RISCV64).ok();

            instructions.push(crate::arch::Instruction {
                raw_instruction,
                address,
                bytes,
            });

            offset += 4;
        }

        instructions
    }

    fn decode_plt_entry(
        plt_entry: &[u8],
        plt_base: u64,
        plt_offset: u64,
    ) -> Option<crate::arch::PltEntry> {
        decode_plt_entry_riscv(plt_entry, plt_base, plt_offset)
    }

    fn should_chain_relocations(chain_prefix: &[Self::RType]) -> bool {
        CHAINS
            .iter()
            .any(|full_chain| full_chain.starts_with(chain_prefix))
    }

    fn get_relocation_base_mask(_relocation_info: &RelocationKindInfo) -> u64 {
        // RISC-V doesn't use page-based addressing like AArch64
        u64::MAX
    }

    fn relocation_to_pc_offset(_relocation_info: &RelocationKindInfo) -> u64 {
        // RISC-V PC-relative addressing is relative to the instruction being executed
        0
    }

    fn is_complete_chain(chain: impl Iterator<Item = Self::RType>) -> bool {
        let chain = chain.collect::<Vec<_>>();
        for candidate in CHAINS {
            if candidate.starts_with(&chain) && *candidate != chain {
                return false;
            }
        }

        // Most RISC-V relocations that have HI/LO in their name can't be used by themselves
        const NOT_IN_ISOLATION: &[RType] = &[
            RType(object::elf::R_RISCV_PCREL_HI20),
            RType(object::elf::R_RISCV_PCREL_LO12_I),
            RType(object::elf::R_RISCV_PCREL_LO12_S),
            RType(object::elf::R_RISCV_HI20),
            RType(object::elf::R_RISCV_LO12_I),
            RType(object::elf::R_RISCV_LO12_S),
            RType(object::elf::R_RISCV_GOT_HI20),
            RType(object::elf::R_RISCV_TLS_GOT_HI20),
            RType(object::elf::R_RISCV_TLS_GD_HI20),
            RType(object::elf::R_RISCV_TPREL_HI20),
            RType(object::elf::R_RISCV_TPREL_LO12_I),
            RType(object::elf::R_RISCV_TPREL_LO12_S),
        ];

        match chain.as_slice() {
            [r_type] => !NOT_IN_ISOLATION.contains(r_type),
            _ => true,
        }
    }

    fn get_basic_value_for_tp_offset() -> crate::asm_diff::BasicValueKind {
        BasicValueKind::TlsOffset
    }
}

// Common RISC-V relocation chains
const CHAINS: &[&[RType]] = &[
    // PC-relative addressing
    &[
        RType(object::elf::R_RISCV_PCREL_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
    &[
        RType(object::elf::R_RISCV_PCREL_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_S),
    ],
    // Absolute addressing
    &[
        RType(object::elf::R_RISCV_HI20),
        RType(object::elf::R_RISCV_LO12_I),
    ],
    &[
        RType(object::elf::R_RISCV_HI20),
        RType(object::elf::R_RISCV_LO12_S),
    ],
    // GOT access
    &[
        RType(object::elf::R_RISCV_GOT_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
    // TLS
    &[
        RType(object::elf::R_RISCV_TPREL_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
];

fn decode_plt_entry_riscv(
    plt_entry: &[u8],
    plt_base: u64,
    plt_offset: u64,
) -> Option<crate::arch::PltEntry> {
    // PLT entry format:
    // auipc  t3, %hi(.got.plt entry)
    // l[w|d] t3, %lo(.got.plt entry)(t3)
    // jalr   t1, t3
    // nop

    if plt_entry.len() < 16 {
        return None;
    }

    let insn1 = u32_from_slice(&plt_entry[0..4]);
    let insn2 = u32_from_slice(&plt_entry[4..8]);
    let insn3 = u32_from_slice(&plt_entry[8..12]);
    let insn4 = u32_from_slice(&plt_entry[12..16]);

    // auipc t3, imm - opcode: 0x17, rd: 28 (t3)
    if (insn1 & 0x7f) != 0x17 || ((insn1 >> 7) & 0x1f) != 28 {
        return None;
    }

    // l[w|d] t3, offset(t3) - opcode: 0x03, rd: 28 (t3), rs1: 28 (t3)
    if (insn2 & 0x7f) != 0x03 || ((insn2 >> 7) & 0x1f) != 28 || ((insn2 >> 15) & 0x1f) != 28 {
        return None;
    }

    // jalr t1, t3 - opcode: 0x67, rd: 6 (t1), rs1: 28 (t3), funct3: 0
    if (insn3 & 0x7f) != 0x67
        || ((insn3 >> 7) & 0x1f) != 6
        || ((insn3 >> 15) & 0x1f) != 28
        || ((insn3 >> 12) & 0x7) != 0
    {
        return None;
    }

    // nop (addi x0, x0, 0) - 0x00000013
    if insn4 != 0x00000013 {
        return None;
    }

    let hi_imm = (insn1 >> 12) as i32;
    let lo_imm = ((insn2 >> 20) as i32) << 20 >> 20;

    let plt_entry_address = plt_base + plt_offset;
    let got_plt_entry = plt_entry_address.wrapping_add(((hi_imm << 12) + lo_imm) as u64);

    Some(crate::arch::PltEntry::DerefJmp(got_plt_entry))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RType(u32);

impl crate::arch::RType for RType {
    fn from_raw(raw: u32) -> Self {
        RType(raw)
    }

    fn from_dynamic_relocation_kind(kind: DynamicRelocationKind) -> Self {
        Self::from_raw(kind.riscv64_r_type())
    }

    fn opt_relocation_info(self) -> Option<RelocationKindInfo> {
        linker_utils::riscv64::relocation_type_from_raw(self.0)
    }

    fn dynamic_relocation_kind(self) -> Option<DynamicRelocationKind> {
        DynamicRelocationKind::from_riscv64_r_type(self.0)
    }

    fn should_ignore_when_computing_referent(self) -> bool {
        false
    }
}

impl Display for RType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&riscv64_rel_type_to_string(self.0), f)
    }
}

impl crate::arch::RelaxationKind for RelaxationKind {
    fn is_no_op(self) -> bool {
        matches!(self, RelaxationKind::NoOp)
    }

    fn is_replace_with_no_op(self) -> bool {
        matches!(self, RelaxationKind::ReplaceWithNop)
    }
}
