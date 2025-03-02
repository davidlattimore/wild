use crate::arch::Arch;
use crate::arch::Instruction;
use crate::arch::PltEntry;
use crate::arch::RType as _;
use crate::arch::Relaxation;
use crate::arch::RelaxationByteRange;
use iced_x86::Formatter as _;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::x86_64_rel_type_to_string;
use linker_utils::utils::u32_from_slice;
use linker_utils::x86_64::RelaxationKind;
use object::SectionKind;
use std::fmt::Display;

const BIT_CLASS: u32 = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct X86_64;

impl Arch for X86_64 {
    type RType = RType;

    type RelaxationKind = linker_utils::x86_64::RelaxationKind;

    type RawInstruction = iced_x86::Instruction;

    const MAX_RELAX_MODIFY_BEFORE: u64 = 4;
    const MAX_RELAX_MODIFY_AFTER: u64 = 19;

    fn next_relocation_modifier(
        relaxation_kind: Self::RelaxationKind,
    ) -> linker_utils::relaxation::RelocationModifier {
        relaxation_kind.next_modifier()
    }

    fn relaxation_byte_range(relaxation: Relaxation<Self>) -> RelaxationByteRange {
        match relaxation.relaxation_kind {
            Self::RelaxationKind::MovIndirectToLea => RelaxationByteRange::new(2, 6),
            Self::RelaxationKind::MovIndirectToAbsolute => RelaxationByteRange::new(2, 6),
            Self::RelaxationKind::RexMovIndirectToAbsolute => RelaxationByteRange::new(3, 7),
            Self::RelaxationKind::RexSubIndirectToAbsolute => RelaxationByteRange::new(3, 7),
            Self::RelaxationKind::RexCmpIndirectToAbsolute => RelaxationByteRange::new(3, 7),
            Self::RelaxationKind::CallIndirectToRelative => RelaxationByteRange::new(2, 6),
            Self::RelaxationKind::JmpIndirectToRelative => RelaxationByteRange::new(2, 6),
            Self::RelaxationKind::TlsGdToLocalExec => RelaxationByteRange::new(4, 16),
            Self::RelaxationKind::TlsGdToLocalExecLarge => RelaxationByteRange::new(3, 22),
            Self::RelaxationKind::TlsGdToInitialExec => RelaxationByteRange::new(4, 16),
            Self::RelaxationKind::TlsLdToLocalExec => RelaxationByteRange::new(3, 12),
            Self::RelaxationKind::TlsLdToLocalExec64 => RelaxationByteRange::new(3, 22),
            Self::RelaxationKind::SkipTlsDescCall => RelaxationByteRange::new(0, 2),
            Self::RelaxationKind::TlsDescToLocalExec => RelaxationByteRange::new(3, 7),
            Self::RelaxationKind::TlsDescToInitialExec => RelaxationByteRange::new(3, 7),
            Self::RelaxationKind::NoOp => match relaxation.new_r_type.0 {
                // TLSDESC_CALL is a relocation that does nothing unless it's optimised away. To
                // verify that it hasn't been optimised away, we need to make sure that we compare
                // the bytes immediately after the relocation.
                object::elf::R_X86_64_TLSDESC_CALL => RelaxationByteRange::new(0, 2),
                _ => RelaxationByteRange::new(0, 0),
            },
        }
    }

    fn possible_relaxations_do(
        r_type: Self::RType,
        section_kind: SectionKind,
        mut cb: impl FnMut(Relaxation<Self>),
    ) {
        let mut no_op_relaxation = Relaxation {
            relaxation_kind: Self::RelaxationKind::NoOp,
            new_r_type: r_type,
            alt_r_type: None,
        };

        let mut relax = |relaxation_kind, new_r_type| {
            let new_r_type = RType::from_raw(new_r_type);
            // We support up to one no-op relaxation with a different relocation kind being grouped
            // with our main no-op relaxation.
            if relaxation_kind == Self::RelaxationKind::NoOp {
                assert!(
                    no_op_relaxation.alt_r_type.is_none(),
                    "Only one secondary r_type is currently supported"
                );

                no_op_relaxation.alt_r_type = Some(new_r_type);
            } else {
                cb(Relaxation {
                    relaxation_kind,
                    new_r_type,
                    alt_r_type: None,
                });
            }
        };

        match (section_kind, r_type.0) {
            (SectionKind::Text, object::elf::R_X86_64_REX_GOTPCRELX) => {
                relax(
                    Self::RelaxationKind::RexMovIndirectToAbsolute,
                    object::elf::R_X86_64_32,
                );
                relax(
                    Self::RelaxationKind::RexSubIndirectToAbsolute,
                    object::elf::R_X86_64_32,
                );
                relax(
                    Self::RelaxationKind::RexCmpIndirectToAbsolute,
                    object::elf::R_X86_64_32,
                );
                relax(
                    Self::RelaxationKind::MovIndirectToLea,
                    object::elf::R_X86_64_PC32,
                );
            }
            (SectionKind::Text, object::elf::R_X86_64_GOTPCRELX) => {
                relax(
                    Self::RelaxationKind::MovIndirectToAbsolute,
                    object::elf::R_X86_64_32,
                );
                relax(
                    Self::RelaxationKind::CallIndirectToRelative,
                    object::elf::R_X86_64_PC32,
                );
                relax(
                    Self::RelaxationKind::MovIndirectToLea,
                    object::elf::R_X86_64_PC32,
                );
                relax(
                    Self::RelaxationKind::JmpIndirectToRelative,
                    object::elf::R_X86_64_PC32,
                );
            }
            (SectionKind::Text, object::elf::R_X86_64_GOTPCREL) => {
                relax(
                    Self::RelaxationKind::MovIndirectToLea,
                    object::elf::R_X86_64_PC32,
                );
            }
            (SectionKind::Text, object::elf::R_X86_64_GOTTPOFF) => {
                relax(
                    Self::RelaxationKind::RexMovIndirectToAbsolute,
                    object::elf::R_X86_64_TPOFF32,
                );
            }
            (SectionKind::Text, object::elf::R_X86_64_PLT32) => {
                relax(Self::RelaxationKind::NoOp, object::elf::R_X86_64_PC32);
            }
            (SectionKind::Text, object::elf::R_X86_64_PLTOFF64) => {
                relax(Self::RelaxationKind::NoOp, object::elf::R_X86_64_GOTOFF64);
            }
            (SectionKind::Text, object::elf::R_X86_64_TLSGD) => {
                relax(
                    Self::RelaxationKind::TlsGdToLocalExec,
                    object::elf::R_X86_64_TPOFF32,
                );
                relax(
                    Self::RelaxationKind::TlsGdToLocalExecLarge,
                    object::elf::R_X86_64_TPOFF32,
                );
                relax(
                    Self::RelaxationKind::TlsGdToInitialExec,
                    object::elf::R_X86_64_GOTTPOFF,
                );
            }
            (SectionKind::Text, object::elf::R_X86_64_TLSLD) => {
                relax(
                    Self::RelaxationKind::TlsLdToLocalExec,
                    object::elf::R_X86_64_NONE,
                );
            }
            (SectionKind::Text, object::elf::R_X86_64_TLSDESC_CALL) => {
                relax(
                    Self::RelaxationKind::SkipTlsDescCall,
                    object::elf::R_X86_64_NONE,
                );
            }
            _ => {}
        };

        cb(no_op_relaxation);
    }

    fn apply_relaxation(
        relaxation_kind: Self::RelaxationKind,
        section_bytes: &mut [u8],
        offset_in_section: &mut u64,
        addend: &mut i64,
    ) {
        relaxation_kind.apply(section_bytes, offset_in_section, addend);
    }

    fn decode_instructions_in_range(
        section_bytes: &[u8],
        section_address: u64,
        function_offset_in_section: u64,
        range: std::ops::Range<u64>,
    ) -> Vec<Instruction<Self>> {
        let mut instructions = Vec::new();

        let mut decoder = AsmDecoder::new(
            section_address + function_offset_in_section,
            &section_bytes[function_offset_in_section as usize..],
        );

        while let Some(instruction) = decoder.next() {
            let instruction_offset = instruction.address() - section_address;

            if instruction_offset >= range.end {
                break;
            }

            let instruction_end = instruction_offset + instruction.bytes.len() as u64;

            if instruction_end > range.start {
                instructions.push(instruction);
            }
        }

        instructions
    }

    fn instruction_to_string(instruction: &Instruction<Self>) -> String {
        let mut out = String::new();
        let mut formatter = iced_x86::GasFormatter::new();
        formatter.format(&instruction.raw_instruction, &mut out);
        out
    }

    fn decode_plt_entry(
        plt_entry: &[u8],
        plt_base: u64,
        plt_offset: u64,
    ) -> Option<crate::arch::PltEntry> {
        return match plt_entry.len() {
            8 => decode_8(plt_entry, plt_base, plt_offset),
            16 => decode_16(plt_entry, plt_base, plt_offset),
            _ => None,
        };

        fn decode_8(plt_entry: &[u8], plt_base: u64, plt_offset: u64) -> Option<PltEntry> {
            const RIP_OFFSET: usize = 6;
            // jmp *{relative GOT}(%rip)
            // xchg %ax, %ax
            if plt_entry.starts_with(&[0xff, 0x25]) && plt_entry.ends_with(&[0x66, 0x90]) {
                let offset = u64::from(u32_from_slice(&plt_entry[RIP_OFFSET - 4..]));
                return Some(PltEntry::DerefJmp(
                    (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
                ));
            }
            None
        }

        fn decode_16(plt_entry: &[u8], plt_base: u64, plt_offset: u64) -> Option<PltEntry> {
            // TODO: We should perhaps report differences in which PLT template was used.
            const PLT_ENTRY_LENGTH: usize = 0x10;
            {
                const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                    0xf2, 0xff, 0x25, 0x0, 0x0, 0x0,
                    0x0, // bnd jmp *{relative GOT address}(%rip)
                    0x0f, 0x1f, 0x44, 0x0, 0x0, // nopl   0x0(%rax,%rax,1)
                ];

                if plt_entry[..7] == PLT_ENTRY_TEMPLATE[..7] {
                    // The offset of the instruction pointer when the jmp instruction is processed -
                    // i.e. the start of the next instruction after the jmp instruction.
                    const RIP_OFFSET: usize = 11;
                    let offset = u64::from(u32_from_slice(&plt_entry[RIP_OFFSET - 4..]));
                    return Some(PltEntry::DerefJmp(
                        (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
                    ));
                }
            }

            {
                const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                    0x68, 0, 0, 0, 0, // push $0
                    0xf2, 0xe9, 0, 0, 0, 0,    // bnd jmp {plt[0]}(%rip)
                    0x90, // nop
                ];
                // Note: Some variants use jmp instead of bnd jmp, then a different padding instruction.
                // Because we use the index that gets pushed, we ignore the bytes of the later
                // instructions, so that we support these variants.
                if plt_entry[..5] == PLT_ENTRY_TEMPLATE[..5] {
                    let index = u32_from_slice(&plt_entry[5..]);
                    return Some(PltEntry::JumpSlot(index));
                }
            }

            {
                const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                    0xff, 0x25, 0, 0, 0, 0, // jmp *{relative GOT address}(%rip)
                    0x68, 0, 0, 0, 0, // push $0
                    0xe9, 0, 0, 0, 0, // jmp {plt[0]}(%rip)
                ];
                if plt_entry[..2] == PLT_ENTRY_TEMPLATE[..2]
                    && plt_entry[6] == PLT_ENTRY_TEMPLATE[6]
                    && plt_entry[11] == PLT_ENTRY_TEMPLATE[11]
                {
                    // The offset of the instruction pointer when the jmp instruction is processed -
                    // i.e. the start of the next instruction after the jmp instruction.
                    const RIP_OFFSET: usize = 6;
                    let offset = u64::from(u32_from_slice(&plt_entry[RIP_OFFSET - 4..]));
                    return Some(PltEntry::DerefJmp(
                        (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
                    ));
                }
            }

            {
                const PLT_ENTRY_TEMPLATE: &[u8; PLT_ENTRY_LENGTH] = &[
                    0x41, 0xbb, 0, 0, 0, 0, // mov $X, %r11d
                    0xff, 0x25, 0, 0, 0, 0, // jmp indirect relative
                    0xcc, 0xcc, 0xcc, 0xcc, // int3 x 4
                ];
                if plt_entry[..2] == PLT_ENTRY_TEMPLATE[..2]
                    && plt_entry[6..8] == PLT_ENTRY_TEMPLATE[6..8]
                    && plt_entry[12..16] == PLT_ENTRY_TEMPLATE[12..16]
                {
                    const RIP_OFFSET: usize = 12;
                    let offset = u64::from(u32_from_slice(&plt_entry[RIP_OFFSET - 4..]));
                    return Some(PltEntry::DerefJmp(
                        (plt_base + plt_offset + RIP_OFFSET as u64).wrapping_add(offset),
                    ));
                }
            }

            // endbr, jmp indirect relative
            let prefix = &[0xf3, 0x0f, 0x1e, 0xfa, 0xff, 0x25];
            if let Some(rest) = plt_entry.strip_prefix(prefix) {
                let offset = u64::from(u32_from_slice(rest));
                return Some(PltEntry::DerefJmp(
                    (plt_base + plt_offset + prefix.len() as u64 + 4).wrapping_add(offset),
                ));
            }

            None
        }
    }

    fn should_chain_relocations(_chain_prefix: &[Self::RType]) -> bool {
        // X86_64 is CISC, so can fit everything into one instruction, so doesn't need to split
        // values between multiple relocations.
        false
    }

    fn get_relocation_base_mask(_relocation_info: &RelocationKindInfo) -> u64 {
        u64::MAX
    }

    fn relocation_to_pc_offset(relocation_info: &RelocationKindInfo) -> u64 {
        // We make somewhat of an assumption here that there are no instruction bytes between our
        // relocation and the next instruction. This isn't necessarily true, but is for the cases
        // where we need to compute this value.
        if let linker_utils::elf::RelocationSize::ByteSize(b) = relocation_info.size {
            b as u64
        } else {
            0
        }
    }

    fn is_complete_chain(_chain: impl Iterator<Item = Self::RType>) -> bool {
        // We don't use relocation chains on x86, so all chains are "complete".
        true
    }
}

struct AsmDecoder<'data> {
    base_address: u64,
    instruction_decoder: iced_x86::Decoder<'data>,
    bytes: &'data [u8],
}

impl<'data> AsmDecoder<'data> {
    fn new(base_address: u64, bytes: &'data [u8]) -> Self {
        let options = iced_x86::DecoderOptions::NONE;
        Self {
            base_address,
            instruction_decoder: iced_x86::Decoder::with_ip(
                BIT_CLASS,
                bytes,
                base_address,
                options,
            ),
            bytes,
        }
    }

    // Note, this could be (and used to be) in an implementation of the Iterator trait. We don't
    // need it to be though, since we always call it directly. By not using a trait, it's easier to
    // find callers of this method.
    fn next(&mut self) -> Option<Instruction<'data, X86_64>> {
        if !self.instruction_decoder.can_decode() {
            return None;
        }
        let offset = self.instruction_decoder.position();
        let instruction = self.instruction_decoder.decode();
        let next_offset = self.instruction_decoder.position();
        let bytes = &self.bytes[offset..next_offset];
        Some(Instruction {
            address: self.base_address + offset as u64,
            raw_instruction: instruction,
            bytes,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RType(u32);

impl crate::arch::RType for RType {
    fn from_raw(raw: u32) -> Self {
        RType(raw)
    }

    fn from_dynamic_relocation_kind(kind: DynamicRelocationKind) -> Self {
        Self::from_raw(kind.x86_64_r_type())
    }

    fn opt_relocation_info(self) -> Option<RelocationKindInfo> {
        linker_utils::x86_64::relocation_kind_and_size(self.0).map(|(kind, size_in_bytes)| {
            RelocationKindInfo {
                kind,
                size: linker_utils::elf::RelocationSize::ByteSize(size_in_bytes),
                mask: None,
                range: linker_utils::elf::AllowedRange::no_check(),
                alignment: 1,
            }
        })
    }

    fn dynamic_relocation_kind(self) -> Option<DynamicRelocationKind> {
        DynamicRelocationKind::from_x86_64_r_type(self.0)
    }
}

impl Display for RType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&x86_64_rel_type_to_string(self.0), f)
    }
}

impl crate::arch::RelaxationKind for RelaxationKind {
    fn is_no_op(self) -> bool {
        matches!(self, RelaxationKind::NoOp)
    }
}
