use crate::ArchKind;
use crate::arch::Arch;
use crate::arch::Instruction;
use crate::arch::Relaxation;
use crate::arch::RelaxationByteRange;
use crate::asm_diff::BasicValueKind;
use crate::utils::decode_insn_with_objdump;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::loongarch64_rel_type_to_string;
use linker_utils::loongarch64::RelaxationKind;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::utils::u32_from_slice;
use std::fmt::Display;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct LoongArch64;

impl Arch for LoongArch64 {
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
        // TODO: Implement relaxation for LoongArch64
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

            let raw_instruction =
                decode_insn_with_objdump(bytes, address, ArchKind::LoongArch64).ok();

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
        decode_plt_entry_loongarch64(plt_entry, plt_base, plt_offset)
    }

    fn should_chain_relocations(chain_prefix: &[Self::RType]) -> bool {
        CHAINS
            .iter()
            .any(|full_chain| full_chain.starts_with(chain_prefix))
    }

    fn get_relocation_base_mask(_relocation_info: &RelocationKindInfo) -> u64 {
        // LoongArch64 uses page-based addressing like AArch64 for some relocations,
        // but we'll use the full mask by default
        u64::MAX
    }

    fn relocation_to_pc_offset(_relocation_info: &RelocationKindInfo) -> u64 {
        0
    }

    fn is_complete_chain(chain: impl Iterator<Item = Self::RType>) -> bool {
        let chain = chain.collect::<Vec<_>>();
        for candidate in CHAINS {
            if candidate.starts_with(&chain) && *candidate != chain {
                return false;
            }
        }

        // LoongArch64 relocations that have HI/LO in their name can't be used by themselves
        const NOT_IN_ISOLATION: &[RType] = &[
            // PC-relative addressing
            RType(object::elf::R_LARCH_PCALA_HI20),
            RType(object::elf::R_LARCH_PCALA_LO12),
            RType(object::elf::R_LARCH_PCALA64_LO20),
            RType(object::elf::R_LARCH_PCALA64_HI12),
            // Absolute addressing
            RType(object::elf::R_LARCH_ABS_HI20),
            RType(object::elf::R_LARCH_ABS_LO12),
            RType(object::elf::R_LARCH_ABS64_LO20),
            RType(object::elf::R_LARCH_ABS64_HI12),
            // GOT access
            RType(object::elf::R_LARCH_GOT_PC_HI20),
            RType(object::elf::R_LARCH_GOT_PC_LO12),
            RType(object::elf::R_LARCH_GOT64_PC_LO20),
            RType(object::elf::R_LARCH_GOT64_PC_HI12),
            // TLS LE
            RType(object::elf::R_LARCH_TLS_LE_HI20),
            RType(object::elf::R_LARCH_TLS_LE_LO12),
            RType(object::elf::R_LARCH_TLS_LE64_LO20),
            RType(object::elf::R_LARCH_TLS_LE64_HI12),
            // TLS IE
            RType(object::elf::R_LARCH_TLS_IE_PC_HI20),
            RType(object::elf::R_LARCH_TLS_IE_PC_LO12),
            RType(object::elf::R_LARCH_TLS_IE64_PC_LO20),
            RType(object::elf::R_LARCH_TLS_IE64_PC_HI12),
            // TLS GD
            RType(object::elf::R_LARCH_TLS_GD_PC_HI20),
            // TLS LD
            RType(object::elf::R_LARCH_TLS_LD_PC_HI20),
            // TLS DESC
            RType(object::elf::R_LARCH_TLS_DESC_PC_HI20),
            RType(object::elf::R_LARCH_TLS_DESC_PC_LO12),
            RType(object::elf::R_LARCH_TLS_DESC64_PC_LO20),
            RType(object::elf::R_LARCH_TLS_DESC64_PC_HI12),
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

const CHAINS: &[&[RType]] = &[
    &[
        RType(object::elf::R_LARCH_PCALA_HI20),
        RType(object::elf::R_LARCH_PCALA_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_PCALA_HI20),
        RType(object::elf::R_LARCH_PCALA64_LO20),
        RType(object::elf::R_LARCH_PCALA64_HI12),
        RType(object::elf::R_LARCH_PCALA_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_ABS_HI20),
        RType(object::elf::R_LARCH_ABS_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_ABS_HI20),
        RType(object::elf::R_LARCH_ABS64_LO20),
        RType(object::elf::R_LARCH_ABS64_HI12),
        RType(object::elf::R_LARCH_ABS_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_GOT_PC_HI20),
        RType(object::elf::R_LARCH_GOT_PC_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_GOT_PC_HI20),
        RType(object::elf::R_LARCH_GOT64_PC_LO20),
        RType(object::elf::R_LARCH_GOT64_PC_HI12),
        RType(object::elf::R_LARCH_GOT_PC_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_LE_HI20),
        RType(object::elf::R_LARCH_TLS_LE_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_LE_HI20),
        RType(object::elf::R_LARCH_TLS_LE64_LO20),
        RType(object::elf::R_LARCH_TLS_LE64_HI12),
        RType(object::elf::R_LARCH_TLS_LE_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_IE_PC_HI20),
        RType(object::elf::R_LARCH_TLS_IE_PC_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_IE_PC_HI20),
        RType(object::elf::R_LARCH_TLS_IE64_PC_LO20),
        RType(object::elf::R_LARCH_TLS_IE64_PC_HI12),
        RType(object::elf::R_LARCH_TLS_IE_PC_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_GD_PC_HI20),
        RType(object::elf::R_LARCH_PCALA_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_LD_PC_HI20),
        RType(object::elf::R_LARCH_PCALA_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_DESC_PC_HI20),
        RType(object::elf::R_LARCH_TLS_DESC_PC_LO12),
    ],
    &[
        RType(object::elf::R_LARCH_TLS_DESC_PC_HI20),
        RType(object::elf::R_LARCH_TLS_DESC64_PC_LO20),
        RType(object::elf::R_LARCH_TLS_DESC64_PC_HI12),
        RType(object::elf::R_LARCH_TLS_DESC_PC_LO12),
    ],
];

fn decode_plt_entry_loongarch64(
    plt_entry: &[u8],
    plt_base: u64,
    plt_offset: u64,
) -> Option<crate::arch::PltEntry> {
    // Try both PLT entry formats
    decode_plt_entry_pcaddu12i(plt_entry, plt_base, plt_offset)
        .or_else(|| decode_plt_entry_pcalau12i(plt_entry, plt_base, plt_offset))
}

/// Decode PLT entry using pcaddu12i instruction
/// Format:
///   pcaddu12i $t3, offset_hi20
///   ld.d      $t3, $t3, offset_lo12
///   jirl      $t1, $t3, 0
///   nop
fn decode_plt_entry_pcaddu12i(
    plt_entry: &[u8],
    plt_base: u64,
    plt_offset: u64,
) -> Option<crate::arch::PltEntry> {
    if plt_entry.len() < 16 {
        return None;
    }

    let insn1 = u32_from_slice(&plt_entry[0..4]);
    let insn2 = u32_from_slice(&plt_entry[4..8]);
    let insn3 = u32_from_slice(&plt_entry[8..12]);

    // pcaddu12i $t3, imm - opcode: 0x0e (bits 31-25), rd: 15 ($t3)
    // Encoding: | imm[31:12] (20 bits) | rd (5 bits) | opcode (7 bits) |
    // Full mask for opcode + rd: 0xfe00001f, expected value: 0x1c00000f
    if (insn1 & 0xfe00001f) != 0x1c00000f {
        return None;
    }

    // ld.d $t3, $t3, offset - opcode: 0x28c (bits 31-22), rd: 15 ($t3), rj: 15 ($t3)
    // Encoding: | imm[11:0] (12 bits) | rj (5 bits) | rd (5 bits) | opcode (10 bits) |
    if (insn2 & 0xffc003ff) != 0x28c001ef {
        return None;
    }

    // jirl $t1, $t3, 0 - opcode: 0x13 (bits 31-26), rd: 13 ($t1), rj: 15 ($t3)
    // Encoding: | imm[17:2] (16 bits) | rj (5 bits) | rd (5 bits) | opcode (6 bits) |
    if (insn3 & 0xfc0003ff) != 0x4c0001ed {
        return None;
    }

    // Extract hi20 from pcaddu12i (bits 24:5)
    let hi_imm = ((insn1 >> 5) & 0xfffff) as i32;
    // Sign extend if negative
    let hi_imm = if hi_imm & 0x80000 != 0 {
        hi_imm | !0xfffff
    } else {
        hi_imm
    };

    // Extract lo12 from ld.d (bits 21:10)
    let lo_imm = ((insn2 >> 10) & 0xfff) as i32;
    let lo_imm = if lo_imm & 0x800 != 0 {
        lo_imm | !0xfff
    } else {
        lo_imm
    };

    let plt_entry_address = plt_base + plt_offset;
    // pcaddu12i computes PC + SignExtend(imm << 12) (no page alignment)
    let base_address = plt_entry_address.wrapping_add(((hi_imm as i64) << 12) as u64);
    let got_plt_entry = base_address.wrapping_add(lo_imm as u64);

    Some(crate::arch::PltEntry::DerefJmp(got_plt_entry))
}

/// Decode PLT entry using pcalau12i instruction (page-aligned variant)
/// Format:
///   pcalau12i $t3, %pc_hi20(.got.plt entry)
///   ld.d      $t3, $t3, %pc_lo12(.got.plt entry)
///   jirl      $t1, $t3, 0
///   nop/break
fn decode_plt_entry_pcalau12i(
    plt_entry: &[u8],
    plt_base: u64,
    plt_offset: u64,
) -> Option<crate::arch::PltEntry> {
    if plt_entry.len() < 16 {
        return None;
    }

    let insn1 = u32_from_slice(&plt_entry[0..4]);
    let insn2 = u32_from_slice(&plt_entry[4..8]);
    let insn3 = u32_from_slice(&plt_entry[8..12]);

    // pcalau12i $t3, imm - opcode: 0x0d (bits 31-25), rd: 15 ($t3)
    // Encoding: | imm[31:12] (20 bits) | rd (5 bits) | opcode (7 bits) |
    // Full mask for opcode + rd: 0xfe00001f, expected value: 0x1a00000f
    if (insn1 & 0xfe00001f) != 0x1a00000f {
        return None;
    }

    // ld.d $t3, $t3, offset - opcode: 0x28c (bits 31-22), rd: 15 ($t3), rj: 15 ($t3)
    // Encoding: | imm[11:0] (12 bits) | rj (5 bits) | rd (5 bits) | opcode (10 bits) |
    if (insn2 & 0xffc003ff) != 0x28c001ef {
        return None;
    }

    // jirl $t1, $t3, 0 - opcode: 0x13 (bits 31-26), rd: 13 ($t1), rj: 15 ($t3)
    // Encoding: | imm[17:2] (16 bits) | rj (5 bits) | rd (5 bits) | opcode (6 bits) |
    if (insn3 & 0xfc0003ff) != 0x4c0001ed {
        return None;
    }

    // Extract hi20 from pcalau12i (bits 24:5)
    let hi_imm = ((insn1 >> 5) & 0xfffff) as i32;
    // Sign extend if negative
    let hi_imm = if hi_imm & 0x80000 != 0 {
        hi_imm | !0xfffff
    } else {
        hi_imm
    };

    // Extract lo12 from ld.d (bits 21:10)
    let lo_imm = ((insn2 >> 10) & 0xfff) as i32;
    // Sign extend if negative
    let lo_imm = if lo_imm & 0x800 != 0 {
        lo_imm | !0xfff
    } else {
        lo_imm
    };

    let plt_entry_address = plt_base + plt_offset;
    // pcalau12i computes (PC + SignExtend(imm << 12)) & ~0xFFF (page aligned)
    let page_address = (plt_entry_address.wrapping_add(((hi_imm as i64) << 12) as u64)) & !0xfff;
    let got_plt_entry = page_address.wrapping_add(lo_imm as u64);

    Some(crate::arch::PltEntry::DerefJmp(got_plt_entry))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RType(u32);

impl crate::arch::RType for RType {
    fn from_raw(raw: u32) -> Self {
        RType(raw)
    }

    fn from_dynamic_relocation_kind(kind: DynamicRelocationKind) -> Self {
        Self::from_raw(kind.loongarch64_r_type())
    }

    fn opt_relocation_info(self) -> Option<RelocationKindInfo> {
        linker_utils::loongarch64::relocation_type_from_raw(self.0)
    }

    fn dynamic_relocation_kind(self) -> Option<DynamicRelocationKind> {
        DynamicRelocationKind::from_loongarch64_r_type(self.0)
    }

    fn should_ignore_when_computing_referent(self) -> bool {
        false
    }
}

impl Display for RType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&loongarch64_rel_type_to_string(self.0), f)
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
