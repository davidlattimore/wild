use crate::elf::PLT_ENTRY_SIZE;
use crate::ensure;
use crate::error;
use crate::error::Result;
use crate::platform::RelaxSymbolInfo;
use crate::platform::Relocation;
use itertools::Itertools;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RISCV_TLS_DTV_OFFSET;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RiscVInstruction;
use linker_utils::elf::riscv64_rel_type_to_string;
use linker_utils::elf::shf;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::relaxation::SectionRelaxDeltas;
use linker_utils::riscv64::JAL_RANGE;
use linker_utils::riscv64::RelaxationKind;
use linker_utils::riscv64::distance_fits_jal;
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

macro_rules! rel_info_from_type {
    ($r_type:expr) => {
        const { relocation_type_from_raw($r_type).unwrap() }
    };
}

impl<'data> crate::platform::Platform<'data> for ElfRiscV64 {
    type Relaxation = Relaxation;
    type File = crate::elf::File<'data>;

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

    #[allow(unused_variables)]
    #[inline(always)]
    fn new_relaxation(
        relocation_kind: u32,
        section_bytes: &[u8],
        offset_in_section: u64,
        flags: crate::value_flags::ValueFlags,
        output_kind: crate::output_kind::OutputKind,
        section_flags: linker_utils::elf::SectionFlags,
        non_zero_address: bool,
        relax_deltas: Option<&SectionRelaxDeltas>,
    ) -> Option<Self::Relaxation>
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
                    if is_jalr_deleted(section_bytes, offset) {
                        // Rewrite auipc into jal.
                        Some(Relaxation {
                            kind: RelaxationKind::CallToJal,
                            rel_info: rel_info_from_type!(object::elf::R_RISCV_JAL),
                            mandatory: output_kind.is_static_executable(),
                        })
                    } else {
                        relocation.kind = RelocationKind::Relative;
                        Some(Relaxation {
                            kind: RelaxationKind::NoOp,
                            rel_info: relocation,
                            mandatory: output_kind.is_static_executable(),
                        })
                    }
                } else {
                    // Target resolved to zero (e.g. weak undef) — replace with nop.
                    Some(Relaxation {
                        kind: RelaxationKind::ReplaceWithNop,
                        rel_info: rel_info_from_type!(object::elf::R_RISCV_NONE),
                        mandatory: output_kind.is_static_executable(),
                    })
                };
            }
            object::elf::R_RISCV_HI20 => {
                if let Some(deltas) = relax_deltas {
                    let input_offset = deltas.output_to_input_offset(offset_in_section);
                    if deltas.has_delta_at(input_offset + 2) {
                        return Some(Relaxation {
                            kind: RelaxationKind::Hi20ToCLui,
                            rel_info: RelaxationKind::clui_rel_info(),
                            mandatory: false,
                        });
                    }
                }
            }

            _ => (),
        }

        None
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Relaxation {
    kind: RelaxationKind,
    rel_info: RelocationKindInfo,
    mandatory: bool,
}

/// Checks whether the paired `jalr` instruction following an `auipc` at `offset` has been removed
/// by a size-changing relaxation.
fn is_jalr_deleted(section_bytes: &[u8], offset: usize) -> bool {
    if offset + 8 > section_bytes.len() {
        return true;
    }

    let auipc_word = u32::from_le_bytes(section_bytes[offset..offset + 4].try_into().unwrap());
    let auipc_rd = (auipc_word >> 7) & 0x1f;
    let next_word = u32::from_le_bytes(section_bytes[offset + 4..offset + 8].try_into().unwrap());
    // jalr opcode = 0x67; rs1 in bits [19:15]
    let is_jalr_with_matching_rs1 =
        (next_word & 0x7f) == 0x67 && ((next_word >> 15) & 0x1f) == auipc_rd;

    !is_jalr_with_matching_rs1
}

impl crate::platform::Relaxation for Relaxation {
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

/// Scan relocations for call relaxation candidates.
///
/// `section_output_address` is the output address of the section being scanned. `existing_deltas`,
/// if present, is used to skip calls that were already relaxed in a previous pass. `resolve_symbol`
/// returns the output address and interposability of a symbol.
pub(crate) fn collect_relaxation_deltas<R: Relocation>(
    section_output_address: u64,
    section_bytes: &[u8],
    relocations: impl Iterator<Item = R>,
    existing_deltas: Option<&SectionRelaxDeltas>,
    mut resolve_symbol: impl FnMut(object::SymbolIndex) -> Option<RelaxSymbolInfo>,
) -> (Vec<(u64, u32)>, Option<u64>) {
    let mut raw_deltas = Vec::new();
    let mut min_unrelaxed_margin: Option<u64> = None;
    let mut prev_call: Option<(u64, object::SymbolIndex)> = None;
    let mut prev_hi20: Option<(u64, object::SymbolIndex, i64)> = None;

    for rel in relocations {
        match rel.raw_type() {
            object::elf::R_RISCV_CALL | object::elf::R_RISCV_CALL_PLT => {
                prev_call = rel.symbol().map(|sym_idx| (rel.offset(), sym_idx));
                prev_hi20 = None;
            }
            object::elf::R_RISCV_HI20 => {
                prev_hi20 = rel
                    .symbol()
                    .map(|sym_idx| (rel.offset(), sym_idx, rel.addend()));
                prev_call = None;
            }
            object::elf::R_RISCV_RELAX => {
                if let Some((call_offset, sym_idx)) = prev_call
                    && rel.offset() == call_offset
                    && !existing_deltas.is_some_and(|d| d.has_delta_at(call_offset + 4))
                {
                    if let Some(info) = resolve_symbol(sym_idx)
                        && !info.is_interposable
                    {
                        let distance = info.output_address as i64
                            - (section_output_address + call_offset) as i64;
                        if distance_fits_jal(distance) {
                            // Delete the jalr instruction (4 bytes at call_offset + 4).
                            raw_deltas.push((call_offset + 4, 4));
                        } else {
                            // Record how far this candidate is from the JAL range boundary so the
                            // caller can decide whether a rescan is worthwhile given the total
                            // bytes deleted so far.
                            let jal_max = JAL_RANGE.end().unsigned_abs();
                            let margin = distance.unsigned_abs() - jal_max;
                            min_unrelaxed_margin =
                                Some(min_unrelaxed_margin.map_or(margin, |m| m.min(margin)));
                        }
                    }
                } else if let Some((hi20_offset, sym_idx, addend)) = prev_hi20
                    && rel.offset() == hi20_offset
                    && !existing_deltas.is_some_and(|d| d.has_delta_at(hi20_offset + 2))
                    && let Some(info) = resolve_symbol(sym_idx)
                    && !info.is_interposable
                {
                    let off = hi20_offset as usize;
                    if off + 4 <= section_bytes.len() {
                        let lui_word =
                            u32::from_le_bytes(section_bytes[off..off + 4].try_into().unwrap());
                        let rd = (lui_word >> 7) & 0x1f;
                        if RelaxationKind::rd_valid_for_clui(rd) {
                            let value = (info.output_address as i64 + addend) as u64;
                            if RelaxationKind::hi20_fits_clui(value) {
                                // Delete the last 2 bytes of the 4-byte lui instruction.
                                raw_deltas.push((hi20_offset + 2, 2));
                            } else {
                                // Compute how far the hi20 value is from the c.lui immediate range
                                // ([-32, -1] ∪ [1, 31]). The hi20 field changes by 1 for every
                                // 0x1000 change in value.
                                let hi20 = value.wrapping_add(0x800) >> 12;
                                let hi20_signed = hi20 as i64;
                                let margin = if hi20_signed > 31 {
                                    ((hi20_signed - 31) as u64) * 0x1000
                                } else if hi20_signed < -32 {
                                    // Address decreases from relaxation push hi20 further negative.
                                    // This can never be fixed.
                                    u64::MAX
                                } else {
                                    // hi20 == 0: need to cross one page boundary.
                                    0x1000u64
                                };
                                min_unrelaxed_margin =
                                    Some(min_unrelaxed_margin.map_or(margin, |m| m.min(margin)));
                            }
                        }
                    }
                }
                prev_call = None;
                prev_hi20 = None;
            }
            _ => {
                prev_call = None;
                prev_hi20 = None;
            }
        }
    }

    (raw_deltas, min_unrelaxed_margin)
}
