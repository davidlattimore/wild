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
use std::fmt::Display;

const DEFAULT_RISCV64_PAGE_SIZE_BITS: u64 = 12;
const DEFAULT_RISCV64_PAGE_IGNORED_MASK: u64 = !((1 << DEFAULT_RISCV64_PAGE_SIZE_BITS) - 1);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Riscv64;

impl Arch for Riscv64 {
    type RType = RType;

    type RelaxationKind = RelaxationKind;

    type RawInstruction = Option<String>;

    const MAX_RELAX_MODIFY_BEFORE: u64 = 0;
    const MAX_RELAX_MODIFY_AFTER: u64 = 4;

    fn relaxation_byte_range(_relaxation: Relaxation<Self>) -> RelaxationByteRange {
        RelaxationByteRange {
            offset_shift: 0,
            num_bytes: 4,
        }
    }

    fn possible_relaxations_do(
        r_type: Self::RType,
        section_kind: object::SectionKind,
        mut cb: impl FnMut(Relaxation<Self>),
    ) {
        let mut relax = |relaxation_kind, new_r_type| {
            cb(Relaxation {
                relaxation_kind,
                new_r_type: RType(new_r_type),
                alt_r_type: None,
            });
        };

        match r_type.0 {
            object::elf::R_RISCV_TLS_GD_HI20 => {
                relax(RelaxationKind::TlsGdToIe, object::elf::R_RISCV_TPREL_HI20);
            }
            object::elf::R_RISCV_CALL | object::elf::R_RISCV_CALL_PLT => {
                if section_kind == object::SectionKind::Text {
                    relax(RelaxationKind::CallToJal, object::elf::R_RISCV_JAL);
                }
            }
            object::elf::R_RISCV_PCREL_HI20 => {
                relax(
                    RelaxationKind::PcrelToDirectAddressing,
                    object::elf::R_RISCV_HI20,
                );
            }
            object::elf::R_RISCV_GOT_HI20 => {
                relax(
                    RelaxationKind::GotToDirectAddressing,
                    object::elf::R_RISCV_HI20,
                );
            }
            _ => {}
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
        section_bytes: &'_ [u8],
        section_address: u64,
        _function_offset_in_section: u64,
        range: std::ops::Range<u64>,
    ) -> Vec<crate::arch::Instruction<'_, Self>> {
        let mut offset = range.start & !3;

        let mut instructions = Vec::new();

        while offset < range.end {
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
        decode_plt_entry_riscv64(plt_entry, plt_base, plt_offset)
    }

    fn is_complete_chain(chain: impl Iterator<Item = Self::RType>) -> bool {
        let chain = chain.collect::<Vec<_>>();

        for candidate in CHAINS {
            if candidate.starts_with(&chain) && *candidate != chain {
                return false;
            }
        }

        const NOT_IN_ISOLATION: &[RType] = &[
            RType(object::elf::R_RISCV_GOT_HI20),
            RType(object::elf::R_RISCV_TLS_GOT_HI20),
            RType(object::elf::R_RISCV_TLS_GD_HI20),
            RType(object::elf::R_RISCV_PCREL_HI20),
            RType(object::elf::R_RISCV_PCREL_LO12_I),
            RType(object::elf::R_RISCV_PCREL_LO12_S),
            RType(object::elf::R_RISCV_HI20),
            RType(object::elf::R_RISCV_LO12_I),
            RType(object::elf::R_RISCV_LO12_S),
            RType(object::elf::R_RISCV_TPREL_HI20),
            RType(object::elf::R_RISCV_LO12_I),
            RType(object::elf::R_RISCV_LO12_S),
        ];

        match chain.as_slice() {
            [r_type] => !NOT_IN_ISOLATION.contains(r_type),
            _ => true,
        }
    }

    fn should_chain_relocations(chain_prefix: &[Self::RType]) -> bool {
        CHAINS
            .iter()
            .any(|full_chain| full_chain.starts_with(chain_prefix))
    }

    fn get_basic_value_for_tp_offset() -> crate::asm_diff::BasicValueKind {
        BasicValueKind::TlsOffset
    }

    fn get_relocation_base_mask(relocation_info: &RelocationKindInfo) -> u64 {
        match relocation_info.mask {
            Some(linker_utils::elf::PageMask::SymbolPlusAddendAndPosition)
            | Some(linker_utils::elf::PageMask::GotEntryAndPosition)
            | Some(linker_utils::elf::PageMask::GotBase) => DEFAULT_RISCV64_PAGE_IGNORED_MASK,
            _ => u64::MAX,
        }
    }

    fn relocation_to_pc_offset(_relocation_info: &RelocationKindInfo) -> u64 {
        0
    }
}

const CHAINS: &[&[RType]] = &[
    // HI20/LO12 pairs for PC-relative addressing
    &[
        RType(object::elf::R_RISCV_PCREL_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
    &[
        RType(object::elf::R_RISCV_PCREL_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_S),
    ],
    // HI20/LO12 pairs for absolute addressing
    &[
        RType(object::elf::R_RISCV_HI20),
        RType(object::elf::R_RISCV_LO12_I),
    ],
    &[
        RType(object::elf::R_RISCV_HI20),
        RType(object::elf::R_RISCV_LO12_S),
    ],
    // TLS related chains
    &[
        RType(object::elf::R_RISCV_TLS_GOT_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
    &[
        RType(object::elf::R_RISCV_TLS_GD_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
    // GOT addressing chains
    &[
        RType(object::elf::R_RISCV_GOT_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
    // Thread pointer relative addressing
    &[
        RType(object::elf::R_RISCV_TPREL_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_I),
    ],
    &[
        RType(object::elf::R_RISCV_TPREL_HI20),
        RType(object::elf::R_RISCV_PCREL_LO12_S),
    ],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RType(u32);

impl crate::arch::RType for RType {
    fn from_raw(raw: u32) -> Self {
        RType(raw)
    }

    fn from_dynamic_relocation_kind(kind: DynamicRelocationKind) -> Self {
        Self::from_raw(kind.riscv64_r_type())
    }

    fn dynamic_relocation_kind(self) -> Option<DynamicRelocationKind> {
        DynamicRelocationKind::from_riscv64_r_type(self.0)
    }

    fn opt_relocation_info(self) -> Option<RelocationKindInfo> {
        linker_utils::riscv64::relocation_type_from_raw(self.0)
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

fn decode_plt_entry_riscv64(
    plt_entry: &[u8],
    plt_base: u64,
    plt_offset: u64,
) -> Option<crate::arch::PltEntry> {
    if plt_entry.len() < 12 {
        return None;
    }

    let got_address = plt_base + plt_offset;
    Some(crate::arch::PltEntry::DerefJmp(got_address))
}
