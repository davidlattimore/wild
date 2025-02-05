use crate::arch::Arch;
use crate::arch::Instruction;
use crate::arch::RType as _;
use crate::arch::Relaxation;
use crate::arch::RelaxationMask;
use iced_x86::Formatter as _;
use linker_utils::elf::x86_64_rel_type_to_string;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::x86_64::RelaxationKind;
use object::SectionKind;
use std::fmt::Display;

const BIT_CLASS: u32 = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct X86_64;

impl Arch for X86_64 {
    type RType = RType;

    type RelaxationKind = linker_utils::x86_64::RelaxationKind;

    type RawInstruction = iced_x86::Instruction;

    fn next_relocation_modifier(
        relaxation_kind: Self::RelaxationKind,
    ) -> linker_utils::relaxation::RelocationModifier {
        relaxation_kind.next_modifier()
    }

    fn relaxation_mask(relaxation: Relaxation<Self>) -> crate::arch::RelaxationMask {
        match relaxation.relaxation_kind {
            Self::RelaxationKind::MovIndirectToLea => RelaxationMask::new(2, &[0xff; 2]),
            Self::RelaxationKind::MovIndirectToAbsolute => RelaxationMask::new(2, &[0xff; 2]),
            Self::RelaxationKind::RexMovIndirectToAbsolute => RelaxationMask::new(3, &[0xff; 3]),
            Self::RelaxationKind::RexSubIndirectToAbsolute => RelaxationMask::new(3, &[0xff; 3]),
            Self::RelaxationKind::RexCmpIndirectToAbsolute => RelaxationMask::new(3, &[0xff; 3]),
            Self::RelaxationKind::CallIndirectToRelative => RelaxationMask::new(2, &[0xff; 2]),
            Self::RelaxationKind::JmpIndirectToRelative => {
                RelaxationMask::new(2, &[0xff, 0, 0, 0, 0, 0xff])
            }
            Self::RelaxationKind::TlsGdToLocalExec => RelaxationMask::new(4, &[0xff; 12]),
            Self::RelaxationKind::TlsGdToLocalExecLarge => RelaxationMask::new(
                3,
                &[
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0,
                    0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                ],
            ),
            Self::RelaxationKind::TlsGdToInitialExec => RelaxationMask::new(4, &[0xff; 12]),
            Self::RelaxationKind::TlsLdToLocalExec => RelaxationMask::new(3, &[0xff; 12]),
            Self::RelaxationKind::TlsLdToLocalExec64 => RelaxationMask::new(3, &[0xff; 18]),
            Self::RelaxationKind::SkipTlsDescCall => RelaxationMask::new(0, &[0xff; 2]),
            Self::RelaxationKind::TlsDescToLocalExec => RelaxationMask::new(3, &[0xff; 3]),
            Self::RelaxationKind::NoOp => match relaxation.new_r_type.0 {
                // TLSDESC_CALL is a relocation that does nothing unless it's optimised away. To
                // verify that it hasn't been optimised away, we need to make sure that we compare
                // the bytes immediately after the relocation.
                object::elf::R_X86_64_TLSDESC_CALL => RelaxationMask::new(0, &[0xff; 2]),
                _ => RelaxationMask::new(0, &[]),
            },
        }
    }

    fn possible_relaxations_do(
        r_type: Self::RType,
        section_kind: SectionKind,
        mut cb: impl FnMut(Relaxation<Self>),
    ) {
        let mut relax = |relaxation_kind, new_r_type| {
            cb(Relaxation {
                relaxation_kind,
                new_r_type: RType::from_raw(new_r_type),
            });
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

        // We always support just keeping the relocation as-is.
        relax(Self::RelaxationKind::NoOp, r_type.0);
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

    fn instruction_to_string(instruction: Self::RawInstruction) -> String {
        let mut out = String::new();
        let mut formatter = iced_x86::GasFormatter::new();
        formatter.format(&instruction, &mut out);
        out
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
            base_address: self.base_address,
            offset: offset as u64,
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

    fn relocation_info(self) -> Option<RelocationKindInfo> {
        linker_utils::x86_64::relocation_kind_and_size(self.0).map(|(kind, size_in_bytes)| {
            RelocationKindInfo {
                kind,
                size: linker_utils::elf::RelocationSize::ByteSize(size_in_bytes),
                mask: None,
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
