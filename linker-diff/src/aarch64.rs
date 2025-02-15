use crate::arch::Arch;
use crate::arch::Instruction;
use crate::arch::Relaxation;
use crate::arch::RelaxationByteRange;
use anyhow::Context;
use anyhow::Result;
use itertools::Itertools;
use linker_utils::aarch64::RelaxationKind;
use linker_utils::aarch64::DEFAULT_AARCH64_PAGE_IGNORED_MASK;
use linker_utils::aarch64::DEFAULT_AARCH64_PAGE_SIZE_BITS;
use linker_utils::elf::aarch64_rel_type_to_string;
use linker_utils::elf::BitMask;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::PageMask;
use linker_utils::elf::RelocationInstruction;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;
use std::fmt::Display;
use std::io::Write;
use std::process::Command;
use std::process::Stdio;
use tempfile::NamedTempFile;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct AArch64;

fn decode_insn_with_objdump(insn: &[u8]) -> Result<String> {
    // TODO: seems objdump cannot read from stdin
    let mut tmpfile = NamedTempFile::new()?;
    tmpfile.write_all(insn)?;
    tmpfile.flush()?;

    let command = Command::new("objdump")
        .arg("-b")
        .arg("binary")
        .arg("-m")
        .arg("aarch64")
        .arg("-D")
        .arg(tmpfile.path())
        .stdout(Stdio::piped())
        .spawn()
        .context("Failed to spawn objdump")?;

    let output = command.wait_with_output().expect("Failed to read stdout");
    // Sample output: 0:	37000008 	tbnz	w8, #0, 0x0
    let insn_line = String::from_utf8_lossy(&output.stdout)
        .lines()
        .last()
        .context("No objdump output")?
        .to_owned();
    Ok(insn_line
        .split_whitespace()
        .skip(2)
        .join(" ")
        .replacen(" ", "\t", 1)
        .to_string())
}

impl Arch for AArch64 {
    type RType = RType;

    type RelaxationKind = RelaxationKind;

    type RawInstruction = Option<String>;

    const MAX_RELAX_MODIFY_BEFORE: u64 = 0;
    const MAX_RELAX_MODIFY_AFTER: u64 = 4;

    fn possible_relaxations_do(
        r_type: Self::RType,
        _section_kind: object::SectionKind,
        mut cb: impl FnMut(crate::arch::Relaxation<Self>),
    ) {
        let mut relax = |relaxation_kind, new_r_type| {
            cb(Relaxation {
                relaxation_kind,
                new_r_type: RType(new_r_type),
                alt_r_type: None,
            });
        };

        match r_type.0 {
            object::elf::R_AARCH64_TLSDESC_ADR_PAGE21 => {
                relax(RelaxationKind::ReplaceWithNop, object::elf::R_AARCH64_NONE);
            }
            object::elf::R_AARCH64_TLSDESC_LD64_LO12 => {
                relax(RelaxationKind::ReplaceWithNop, object::elf::R_AARCH64_NONE);
            }
            object::elf::R_AARCH64_TLSDESC_ADD_LO12 => {
                relax(
                    RelaxationKind::MovzX0Lsl16,
                    object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1,
                );
            }
            object::elf::R_AARCH64_TLSDESC_CALL => {
                relax(
                    RelaxationKind::MovkX0,
                    object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC,
                );
            }
            object::elf::R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21 => {
                relax(
                    RelaxationKind::MovzXnLsl16,
                    object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G1,
                );
            }
            object::elf::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC => {
                relax(
                    RelaxationKind::MovkXn,
                    object::elf::R_AARCH64_TLSLE_MOVW_TPREL_G0_NC,
                );
            }
            object::elf::R_AARCH64_CALL26 => {
                relax(RelaxationKind::ReplaceWithNop, object::elf::R_AARCH64_NONE);
            }
            object::elf::R_AARCH64_JUMP26 => {
                relax(RelaxationKind::ReplaceWithNop, object::elf::R_AARCH64_NONE);
            }
            object::elf::R_AARCH64_ADR_GOT_PAGE => {
                relax(
                    RelaxationKind::AdrpToAdr,
                    object::elf::R_AARCH64_ADR_PREL_LO21,
                );
            }
            object::elf::R_AARCH64_ADR_PREL_PG_HI21 => {
                relax(
                    RelaxationKind::AdrpToAdr,
                    object::elf::R_AARCH64_ADR_PREL_LO21,
                );
            }
            _ => {}
        }

        relax(Self::RelaxationKind::NoOp, r_type.0);
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
    ) -> Vec<crate::arch::Instruction<Self>> {
        let mut offset = range.start & !3;

        let mut instructions = Vec::new();

        while offset < range.end {
            let bytes = &section_bytes[offset as usize..offset as usize + 4];
            let raw_instruction = decode_insn_with_objdump(bytes).ok();

            instructions.push(crate::arch::Instruction {
                raw_instruction,
                address: section_address + offset,
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
        decode_plt_entry_template_1(plt_entry, plt_base, plt_offset)
            .or_else(|| decode_plt_entry_template_2(plt_entry, plt_base, plt_offset))
    }

    fn should_chain_relocations(chain_prefix: &[Self::RType]) -> bool {
        CHAINS
            .iter()
            .any(|full_chain| full_chain.starts_with(chain_prefix))
    }

    fn get_relocation_base_mask(relocation_info: &RelocationKindInfo) -> u64 {
        match relocation_info.mask {
            Some(
                PageMask::SymbolPlusAddendAndPosition
                | PageMask::GotEntryAndPosition
                | PageMask::GotBase,
            ) => linker_utils::aarch64::DEFAULT_AARCH64_PAGE_IGNORED_MASK,
            _ => u64::MAX,
        }
    }

    fn relocation_to_pc_offset(_relocation_info: &RelocationKindInfo) -> u64 {
        // ARM PC-relative addressing is always relative to the instruction being executed, not the
        // next instruction. Also, the relocations always point to the start of the instruction.
        // These two facts combined mean that our offset here is always zero.
        0
    }

    fn is_complete_chain(chain: impl Iterator<Item = Self::RType>) -> bool {
        let chain = chain.collect::<Vec<_>>();
        for candidate in CHAINS {
            if candidate.starts_with(&chain) && *candidate != chain {
                return false;
            }
        }

        // All relocation types that have LO or HI in their name can't be used by themselves.
        const NOT_IN_ISOLATION: &[RType] = &[
            RType(object::elf::R_AARCH64_LD_PREL_LO19),
            RType(object::elf::R_AARCH64_ADR_PREL_LO21),
            RType(object::elf::R_AARCH64_ADR_PREL_PG_HI21),
            RType(object::elf::R_AARCH64_ADR_PREL_PG_HI21_NC),
            RType(object::elf::R_AARCH64_ADD_ABS_LO12_NC),
            RType(object::elf::R_AARCH64_LDST8_ABS_LO12_NC),
            RType(object::elf::R_AARCH64_LDST16_ABS_LO12_NC),
            RType(object::elf::R_AARCH64_LDST32_ABS_LO12_NC),
            RType(object::elf::R_AARCH64_LDST64_ABS_LO12_NC),
            RType(object::elf::R_AARCH64_LDST128_ABS_LO12_NC),
            RType(object::elf::R_AARCH64_LD64_GOTOFF_LO15),
            RType(object::elf::R_AARCH64_LD64_GOT_LO12_NC),
            RType(object::elf::R_AARCH64_LD64_GOTPAGE_LO15),
            RType(object::elf::R_AARCH64_TLSGD_ADD_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLD_ADD_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLD_ADD_DTPREL_HI12),
            RType(object::elf::R_AARCH64_TLSLD_ADD_DTPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLD_ADD_DTPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLD_LDST8_DTPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLD_LDST8_DTPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLD_LDST16_DTPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLD_LDST16_DTPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLD_LDST32_DTPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLD_LDST32_DTPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLD_LDST64_DTPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLD_LDST64_DTPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLE_ADD_TPREL_HI12),
            RType(object::elf::R_AARCH64_TLSLE_ADD_TPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLE_ADD_TPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLE_LDST8_TPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLE_LDST8_TPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLE_LDST16_TPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLE_LDST16_TPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLE_LDST32_TPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLE_LDST32_TPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLE_LDST64_TPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLE_LDST64_TPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSDESC_LD64_LO12),
            RType(object::elf::R_AARCH64_TLSDESC_ADD_LO12),
            RType(object::elf::R_AARCH64_TLSLE_LDST128_TPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLE_LDST128_TPREL_LO12_NC),
            RType(object::elf::R_AARCH64_TLSLD_LDST128_DTPREL_LO12),
            RType(object::elf::R_AARCH64_TLSLD_LDST128_DTPREL_LO12_NC),
        ];

        match chain.as_slice() {
            [r_type] => !NOT_IN_ISOLATION.contains(r_type),
            _ => true,
        }
    }
}

const CHAINS: &[&[RType]] = &[
    &[
        RType(object::elf::R_AARCH64_ADR_PREL_PG_HI21),
        RType(object::elf::R_AARCH64_ADD_ABS_LO12_NC),
    ],
    &[
        RType(object::elf::R_AARCH64_ADR_PREL_PG_HI21),
        RType(object::elf::R_AARCH64_LDST64_ABS_LO12_NC),
    ],
    &[
        RType(object::elf::R_AARCH64_TLSDESC_ADR_PAGE21),
        RType(object::elf::R_AARCH64_TLSDESC_LD64_LO12),
        RType(object::elf::R_AARCH64_TLSDESC_ADD_LO12),
        RType(object::elf::R_AARCH64_TLSDESC_CALL),
    ],
    &[
        RType(object::elf::R_AARCH64_ADR_GOT_PAGE),
        RType(object::elf::R_AARCH64_LD64_GOT_LO12_NC),
    ],
    &[
        RType(object::elf::R_AARCH64_TLSLE_ADD_TPREL_HI12),
        RType(object::elf::R_AARCH64_TLSLE_ADD_TPREL_LO12_NC),
    ],
    &[
        RType(object::elf::R_AARCH64_TLSIE_ADR_GOTTPREL_PAGE21),
        RType(object::elf::R_AARCH64_TLSIE_LD64_GOTTPREL_LO12_NC),
    ],
];

const REL_ADR_PAGE: BitMask = BitMask::new(
    RelocationInstruction::Adr,
    DEFAULT_AARCH64_PAGE_SIZE_BITS as u32,
    DEFAULT_AARCH64_PAGE_SIZE_BITS as u32 + 21,
);

const REL_LDR_OFFSET: BitMask = BitMask::new(RelocationInstruction::LdrRegister, 3, 3 + 12);

const REL_ADD_LITERAL: BitMask = BitMask::new(RelocationInstruction::Add, 0, 12);

fn decode_plt_entry_template_1(
    plt_entry: &[u8],
    plt_base: u64,
    plt_offset: u64,
) -> Option<crate::arch::PltEntry> {
    const PLT_ENTRY_TEMPLATE: &[u8] = &[
        0x10, 0x00, 0x00, 0x90, // adrp x16, page(&(.got.plt[n]))
        0x11, 0x02, 0x40, 0xf9, // ldr x17, [x16, offset(&(.got.plt[n]))]
        0x20, 0x02, 0x1f, 0xd6, // br x17
        0x1f, 0x20, 0x03, 0xd5, // nop
    ];

    let values = extract_values_from_template(
        plt_entry,
        PLT_ENTRY_TEMPLATE,
        &[(0, REL_ADR_PAGE), (4, REL_LDR_OFFSET)],
    )?;

    let entry_page_base = (plt_base + plt_offset) & DEFAULT_AARCH64_PAGE_IGNORED_MASK;

    let got_address = entry_page_base.wrapping_add(values[0]) | values[1];

    Some(crate::arch::PltEntry::DerefJmp(got_address))
}

fn decode_plt_entry_template_2(
    plt_entry: &[u8],
    plt_base: u64,
    plt_offset: u64,
) -> Option<crate::arch::PltEntry> {
    const PLT_ENTRY_TEMPLATE: &[u8] = &[
        0xf0, 0x02, 0x00, 0xb0, // adrp x16, page(&(.got.plt[n]))
        0x11, 0x0e, 0x47, 0xf9, // ldr x17, [x16, offset(&(.got.plt[n]))]
        0x10, 0x62, 0x38, 0x91, // add x16, x16, #0xe20
        0x20, 0x02, 0x1f, 0xd6, // br x17
    ];

    let values = extract_values_from_template(
        plt_entry,
        PLT_ENTRY_TEMPLATE,
        &[(0, REL_ADR_PAGE), (4, REL_LDR_OFFSET), (8, REL_ADD_LITERAL)],
    )?;

    let entry_page_base = (plt_base + plt_offset) & DEFAULT_AARCH64_PAGE_IGNORED_MASK;

    // Note, we ignore the value of the third relocation - the one associated with the add
    // instruction. It's only needed for lazy PLT entries, but some linkers have the add instruction
    // even when -z now is passed.

    let got_address = entry_page_base.wrapping_add(values[0]) | values[1];

    Some(crate::arch::PltEntry::DerefJmp(got_address))
}

/// Extracts the relocation values from `plt_entry`, making sure that the non-relocation parts match
/// `template`.
fn extract_values_from_template(
    plt_entry: &[u8],
    template: &[u8],
    relocations: &[(usize, BitMask)],
) -> Option<Vec<u64>> {
    if plt_entry.len() != template.len() {
        return None;
    }

    let mut mask = vec![0; template.len()];

    for (offset, rel) in relocations {
        let num_bits = rel.range.end - rel.range.start;
        rel.instruction
            .write_to_value((1 << num_bits) - 1, false, &mut mask[*offset..offset + 4]);
    }

    for m in &mut mask {
        *m = !*m;
    }

    if !equal_with_mask(plt_entry, template, &mask) {
        return None;
    }

    Some(
        relocations
            .iter()
            .map(|(offset, rel)| {
                let raw_value = rel
                    .instruction
                    .read_value(&plt_entry[*offset..offset + 4])
                    .0;
                raw_value << rel.range.start
            })
            .collect(),
    )
}

fn equal_with_mask(a: &[u8], b: &[u8], mask: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), mask.len());
    a.iter()
        .zip(b)
        .zip(mask)
        .all(|((a, b), m)| (a & m) == (b & m))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RType(u32);

impl crate::arch::RType for RType {
    fn from_raw(raw: u32) -> Self {
        RType(raw)
    }

    fn from_dynamic_relocation_kind(kind: DynamicRelocationKind) -> Self {
        Self::from_raw(kind.aarch64_r_type())
    }

    fn opt_relocation_info(self) -> Option<RelocationKindInfo> {
        linker_utils::aarch64::relocation_type_from_raw(self.0)
    }

    fn dynamic_relocation_kind(self) -> Option<DynamicRelocationKind> {
        DynamicRelocationKind::from_aarch64_r_type(self.0)
    }
}

impl Display for RType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&aarch64_rel_type_to_string(self.0), f)
    }
}

impl crate::arch::RelaxationKind for RelaxationKind {
    fn is_no_op(self) -> bool {
        matches!(self, RelaxationKind::NoOp)
    }
}
