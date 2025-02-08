use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;
use std::fmt::Debug;
use std::fmt::Display;
use std::ops::Range;

/// Provides architecture-specific functionality needed by linker-diff.
pub(crate) trait Arch: Clone + Copy + Eq + PartialEq + Debug {
    /// The type of relocations on this architecture.
    type RType: RType;

    /// A type representing relaxations on this architecture.
    type RelaxationKind: RelaxationKind;

    /// A type representing a decoded instruction on this architecture.
    type RawInstruction: Copy + Clone;

    /// Calls `cb` with each relaxation that we think is possible for the supplied relocation type and
    /// section kind.
    fn possible_relaxations_do(
        r_type: Self::RType,
        section_kind: object::SectionKind,
        cb: impl FnMut(Relaxation<Self>),
    );

    /// Returns a mask that can be used to identify the supplied relaxation.
    fn relaxation_mask(relaxation: Relaxation<Self>, relocation_offset: usize) -> RelaxationMask {
        let byte_range = Self::relaxation_byte_range(relaxation);

        let mut mask = RelaxationMask {
            offset_shift: byte_range.offset_shift,
            bitmask: Vec::new(),
        };

        if let Some(info) = relaxation.new_r_type.relocation_info() {
            match info.size {
                linker_utils::elf::RelocationSize::ByteSize(num_bytes) => {
                    let mask_len = (relocation_offset + num_bytes).max(byte_range.num_bytes);

                    mask.bitmask.resize(mask_len, 0xff);

                    for b in &mut mask.bitmask[relocation_offset..relocation_offset + num_bytes] {
                        *b = 0;
                    }
                }
                linker_utils::elf::RelocationSize::BitMasking { range, insn } => {
                    mask.bitmask.resize(4, 0);

                    // To figure out which bits are part of the relocation, we write a value with
                    // all ones into a buffer that initially contains zeros.
                    let all_ones = (1 << (range.end - range.start)) - 1;
                    insn.write_to_value(all_ones, false, &mut mask.bitmask);

                    // Wherever we get a 1 is part of the relocation, so invert all bits.
                    for b in &mut mask.bitmask {
                        *b = !*b;
                    }
                }
            }
        }

        mask
    }

    fn relaxation_byte_range(relaxation: Relaxation<Self>) -> RelaxationByteRange;

    /// Applies the supplied relaxation to `section_bytes`, possibly also updating
    /// `offset_in_section` and `addend` according to the relaxation kind.
    fn apply_relaxation(
        relaxation_kind: Self::RelaxationKind,
        section_bytes: &mut [u8],
        offset_in_section: &mut u64,
        addend: &mut i64,
    );

    /// Returns whether the next relocation should be skipped based on a relaxation applied to the
    /// current relocation.
    fn next_relocation_modifier(relaxation_kind: Self::RelaxationKind) -> RelocationModifier;

    /// Returns a human readable form of the supplied instruction.
    fn instruction_to_string(instruction: Self::RawInstruction) -> String;

    /// Decode instructions that are in or overlap with the supplied range. The start of `range` may
    /// be part way through an instruction. For variable length instructions, implementations will
    /// want to start decoding from the start of the function. For fixed size instructions, it
    /// should be possible to start at or just prior to the start of `range`.
    fn decode_instructions_in_range(
        section_bytes: &[u8],
        section_address: u64,
        function_offset_in_section: u64,
        range: Range<u64>,
    ) -> Vec<Instruction<Self>>;

    fn decode_plt_entry(plt_entry: &[u8], plt_base: u64, plt_offset: u64) -> Option<PltEntry>;
}

pub(crate) trait RType: Copy + Debug + Display + Eq + PartialEq {
    fn from_raw(raw: u32) -> Self;

    fn from_dynamic_relocation_kind(kind: DynamicRelocationKind) -> Self;

    fn relocation_info(self) -> Option<RelocationKindInfo>;

    fn dynamic_relocation_kind(self) -> Option<DynamicRelocationKind>;
}

pub(crate) trait RelaxationKind: Copy + Clone + Debug + Eq + PartialEq {
    /// Returns whether this relaxation does nothing.
    fn is_no_op(self) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Relaxation<A: Arch> {
    pub(crate) relaxation_kind: A::RelaxationKind,
    pub(crate) new_r_type: A::RType,
}

/// The range of bytes to which a relaxation applies.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelaxationByteRange {
    /// Number of bytes prior to the offset of the original relocation at which the bitmask starts.
    pub(crate) offset_shift: u64,

    /// Number of bytes covered by this relaxation, including bytes in which the relocation will be
    /// written.
    pub(crate) num_bytes: usize,
}

impl RelaxationByteRange {
    pub(crate) fn new(offset_shift: u64, num_bytes: usize) -> Self {
        Self {
            offset_shift,
            num_bytes,
        }
    }
}

/// A bitmask used for comparing the bytes produced by a relaxation with the bytes in the actual
/// file.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RelaxationMask {
    /// Number of bytes prior to the offset of the original relocation at which the bitmask starts.
    pub(crate) offset_shift: u64,

    /// Which bits should be considered part of the instructions modified by a particular
    /// relaxation. e.g. a byte of 0xff would indicate that all bits of the corresponding byte
    /// should be treated as part of the instruction. A 0 byte would indicate that the corresponding
    /// byte should not be compared - i.e. if it's part of the offset written by the new relocation.
    /// Note that bytes that are part of the instruction should still be compared even if they're
    /// not written by the relocation, since the fact that the byte wasn't changed is important in
    /// identifying a particular relaxation.
    ///
    /// Example: 48 8d 3d 00 00 00 00    lea    0x0(%rip),%rdi
    ///                   ^ The relocation points here
    ///
    /// The offset_shift would be -3 so as to point to the start of the instruction (0x48).
    ///
    /// The mask would be [0xff, 0xff, 0xff] since the first three bytes of the instruction should
    /// be compared in their entirety.
    pub(crate) bitmask: Vec<u8>,
}

impl RelaxationMask {
    /// Returns whether `a` == `b`, ignoring bits where the corresponding bit in our mask is 0.
    pub(crate) fn matches(&self, a: &[u8], b: &[u8]) -> bool {
        assert_eq!(a.len(), b.len());

        self.bitmask
            .iter()
            .zip(a)
            .zip(b)
            .all(|((mask, value_a), value_b)| (*value_a & mask) == (*value_b & mask))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Instruction<'data, A: Arch> {
    pub(crate) raw_instruction: A::RawInstruction,

    /// The address of the start of the function that contained this instruction.
    pub(crate) base_address: u64,

    /// The offset of this instruction within the function.
    pub(crate) offset: u64,

    pub(crate) bytes: &'data [u8],
}

impl<A: Arch> Instruction<'_, A> {
    pub(crate) fn address(&self) -> u64 {
        self.base_address + self.offset
    }
}

pub(crate) enum PltEntry {
    /// The parameter is an address (most likely of a GOT entry) that will be dereferenced by the
    /// PLT entry then jumped to.
    DerefJmp(u64),

    /// The parameter is an index into .rela.plt.
    JumpSlot(u32),
}
