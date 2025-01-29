use crate::elf::RelocationKind;
use crate::relaxation::RelocationModifier;

#[derive(Debug, Clone, Copy)]
pub enum RelaxationKind {
    /// Transforms a mov instruction that would have loaded an address to not use the GOT. The
    /// transformation will look like `mov *x(%rip), reg` -> `lea x(%rip), reg`.
    MovIndirectToLea,

    /// Transforms a mov instruction that would have loaded an absolute value to not use the GOT.
    /// The transformation will look like `mov *x(%rip), reg` ->  `mov x, reg`.
    MovIndirectToAbsolute,

    /// Transforms a mov instruction that would have loaded an absolute value to not use the GOT.
    /// The transformation will look like `mov *x(%rip), reg` ->  `mov x, reg`.
    RexMovIndirectToAbsolute,

    // Transforms an indirect sub to an absolute sub.
    RexSubIndirectToAbsolute,

    // Transforms an indirect cmp to an absolute cmp.
    RexCmpIndirectToAbsolute,

    /// Transform a call instruction like `call *x(%rip)` -> `call x(%rip)`.
    CallIndirectToRelative,

    /// Leave the instruction alone. Used when we only want to change the kind of relocation used.
    NoOp,

    /// Transform general dynamic (GD) into local exec.
    TlsGdToLocalExec,

    /// As above, but for the large-model form of the instruction.
    TlsGdToLocalExecLarge,

    /// Transform local dynamic (LD) into local exec.
    TlsLdToLocalExec,

    /// Transform local dynamic (LD) into local exec with extra padding because the previous
    /// instruction was 64 bit.
    TlsLdToLocalExec64,

    /// Transform general dynamic (GD) into initial exec
    TlsGdToInitialExec,
}

impl RelaxationKind {
    pub fn apply(self, section_bytes: &mut [u8], offset_in_section: &mut u64, addend: &mut i64) {
        let offset = *offset_in_section as usize;
        match self {
            RelaxationKind::MovIndirectToLea => {
                // Since the value is an address, we transform a PC-relative mov into a PC-relative
                // lea.
                section_bytes[offset - 2] = 0x8d;
            }
            RelaxationKind::MovIndirectToAbsolute => {
                // Turn a PC-relative mov into an absolute mov.
                section_bytes[offset - 2] = 0xc7;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xc0;
                *addend = 0;
            }
            RelaxationKind::RexMovIndirectToAbsolute => {
                // Turn a PC-relative mov into an absolute mov.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0xc7;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xc0;
                *addend = 0;
            }
            RelaxationKind::RexSubIndirectToAbsolute => {
                // Turn a PC-relative sub into an absolute sub.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0x81;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xe8;
                *addend = 0;
            }
            RelaxationKind::RexCmpIndirectToAbsolute => {
                // Turn a PC-relative cmp into an absolute cmp.
                let rex = section_bytes[offset - 3];
                section_bytes[offset - 3] = (rex & !4) | ((rex & 4) >> 2);
                section_bytes[offset - 2] = 0x81;
                let mod_rm = &mut section_bytes[offset - 1];
                *mod_rm = (*mod_rm >> 3) & 0x7 | 0xf8;
                *addend = 0;
            }
            RelaxationKind::CallIndirectToRelative => {
                section_bytes[offset - 2..offset].copy_from_slice(&[0x67, 0xe8]);
            }
            RelaxationKind::TlsGdToLocalExec => {
                section_bytes[offset - 4..offset + 8].copy_from_slice(&[
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0,%rax
                    0x48, 0x8d, 0x80, // lea {offset}(%rax),%rax
                ]);
                *offset_in_section += 8;
                *addend = 0;
            }
            RelaxationKind::TlsGdToLocalExecLarge => {
                section_bytes[offset - 3..offset + 19].copy_from_slice(&[
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // mov %fs:0,%rax
                    0x48, 0x8d, 0x80, 0, 0, 0, 0, // lea {offset}(%rax),%rax
                    0x66, 0x0f, 0x1f, 0x44, 0, 0, // nopw (%rax,%rax)
                ]);
                *offset_in_section += 9;
                *addend = 0;
            }
            RelaxationKind::TlsGdToInitialExec => {
                section_bytes[offset - 4..offset + 8].copy_from_slice(&[
                    // mov %fs:0,%rax
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0, // add *x,%rax
                    0x48, 0x03, 0x05,
                ]);
                *offset_in_section += 8;
                *addend = -12_i64;
            }
            RelaxationKind::TlsLdToLocalExec => {
                section_bytes[offset - 3..offset + 9].copy_from_slice(&[
                    // mov %fs:0,%rax
                    0x66, 0x66, 0x66, 0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
                ]);
                *offset_in_section += 5;
            }
            RelaxationKind::TlsLdToLocalExec64 => {
                section_bytes[offset - 3..offset + 19].copy_from_slice(&[
                    // nopw (%rax,%rax)
                    0x66, 0x66, 0x66, 0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0,
                    // mov %fs:0,%rax
                    0x64, 0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0,
                ]);
                *offset_in_section += 15;
            }
            RelaxationKind::NoOp => {}
        }
    }

    #[must_use]
    pub fn next_modifier(&self) -> RelocationModifier {
        match self {
            RelaxationKind::TlsGdToInitialExec
            | RelaxationKind::TlsGdToLocalExec
            | RelaxationKind::TlsGdToLocalExecLarge
            | RelaxationKind::TlsLdToLocalExec
            | RelaxationKind::TlsLdToLocalExec64 => RelocationModifier::SkipNextRelocation,
            _ => RelocationModifier::Normal,
        }
    }
}

/// Returns the supplied x86-64 relocation type split into a relocation kind and a size (in bytes)
/// for the relocation. Returns `None` if the r_type isn't recognised.
#[must_use]
pub fn relocation_kind_and_size(r_type: u32) -> Option<(RelocationKind, usize)> {
    let (kind, size) = match r_type {
        object::elf::R_X86_64_64 => (RelocationKind::Absolute, 8),
        object::elf::R_X86_64_PC32 => (RelocationKind::Relative, 4),
        object::elf::R_X86_64_PC64 => (RelocationKind::Relative, 8),
        object::elf::R_X86_64_GOT32 => (RelocationKind::GotRelGotBase, 4),
        object::elf::R_X86_64_GOT64 => (RelocationKind::GotRelGotBase, 8),
        object::elf::R_X86_64_GOTOFF64 => (RelocationKind::SymRelGotBase, 8),
        object::elf::R_X86_64_PLT32 => (RelocationKind::PltRelative, 4),
        object::elf::R_X86_64_PLTOFF64 => (RelocationKind::PltRelGotBase, 8),
        object::elf::R_X86_64_GOTPCREL => (RelocationKind::GotRelative, 4),

        // For now, we rely on GOTPC64 and GOTPC32 always referencing the symbol
        // _GLOBAL_OFFSET_TABLE_, which means that we can just treat these a normal relative
        // relocations and avoid any special processing when writing.
        object::elf::R_X86_64_GOTPC64 => (RelocationKind::Relative, 8),
        object::elf::R_X86_64_GOTPC32 => (RelocationKind::Relative, 4),

        object::elf::R_X86_64_32 | object::elf::R_X86_64_32S => (RelocationKind::Absolute, 4),
        object::elf::R_X86_64_16 => (RelocationKind::Absolute, 2),
        object::elf::R_X86_64_PC16 => (RelocationKind::Relative, 2),
        object::elf::R_X86_64_8 => (RelocationKind::Absolute, 1),
        object::elf::R_X86_64_PC8 => (RelocationKind::Relative, 1),
        object::elf::R_X86_64_TLSGD => (RelocationKind::TlsGd, 4),
        object::elf::R_X86_64_TLSLD => (RelocationKind::TlsLd, 4),
        object::elf::R_X86_64_DTPOFF32 => (RelocationKind::DtpOff, 4),
        object::elf::R_X86_64_DTPOFF64 => (RelocationKind::DtpOff, 8),
        object::elf::R_X86_64_GOTTPOFF => (RelocationKind::GotTpOff, 4),
        object::elf::R_X86_64_GOTPCRELX | object::elf::R_X86_64_REX_GOTPCRELX => {
            (RelocationKind::GotRelative, 4)
        }
        object::elf::R_X86_64_TPOFF32 => (RelocationKind::TpOff, 4),
        object::elf::R_X86_64_GOTPC32_TLSDESC => (RelocationKind::TlsDesc, 4),
        object::elf::R_X86_64_TLSDESC_CALL => (RelocationKind::TlsDescCall, 0),
        object::elf::R_X86_64_NONE => (RelocationKind::None, 0),
        _ => return None,
    };
    Some((kind, size))
}
