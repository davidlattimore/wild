use crate::elf::PLT_ENTRY_SIZE;
use crate::error;
use crate::error::Result;
use crate::platform::Platform;
use itertools::Itertools;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::PAGE_MASK_4KB;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::SIZE_2KB;
use linker_utils::elf::loongarch64_rel_type_to_string;
use linker_utils::elf::shf;
use linker_utils::loongarch64::RelaxationKind;
use linker_utils::loongarch64::relocation_type_from_raw;
use linker_utils::relaxation::RelocationModifier;
use linker_utils::utils::or_from_slice;

pub(crate) struct ElfLoongArch64;

const PLT_ENTRY_TEMPLATE: &[u8] = &[
    0x0f, 0x0, 0x0, 0x1a, // pcalau12i $t3, offset_high(&(.got.plt[n])
    0xef, 0x1, 0xc0, 0x28, // ld.d $t3, $t3,offset_low(&(.got.plt[n])(t3)
    0xed, 0x1, 0x0, 0x4c, // jirl $t1, $t3, 0
    0x0, 0x0, 0x2a, 0x0, // break
];

const _ASSERTS: () = {
    assert!(PLT_ENTRY_TEMPLATE.len() as u64 == PLT_ENTRY_SIZE);
};

impl crate::platform::Platform for ElfLoongArch64 {
    type Relaxation = Relaxation;
    type Format = crate::elf::Elf;

    const KIND: crate::arch::Architecture = crate::arch::Architecture::LoongArch64;

    fn elf_header_arch_magic() -> u16 {
        object::elf::EM_LOONGARCH
    }

    #[inline(always)]
    fn relocation_from_raw(r_type: u32) -> Result<RelocationKindInfo> {
        linker_utils::loongarch64::relocation_type_from_raw(r_type).ok_or_else(|| {
            error!(
                "Unsupported relocation type {}",
                Self::rel_type_to_string(r_type)
            )
        })
    }

    fn get_dynamic_relocation_type(relocation: DynamicRelocationKind) -> u32 {
        relocation.loongarch64_r_type()
    }

    fn rel_type_to_string(r_type: u32) -> std::borrow::Cow<'static, str> {
        loongarch64_rel_type_to_string(r_type)
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
        let pcala_hi20 =
            ((((got_address + SIZE_2KB) & !PAGE_MASK_4KB) - (plt_address & !PAGE_MASK_4KB)) >> 12)
                << 5;
        let pcala_lo12 = (got_address & 0xfff) << 10;
        or_from_slice(&mut plt_entry[0..4], &(pcala_hi20 as u32).to_le_bytes());
        or_from_slice(&mut plt_entry[4..8], &(pcala_lo12 as u32).to_le_bytes());
        Ok(())
    }

    fn get_dtv_offset() -> u64 {
        0
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

    fn merge_eflags(mut eflags: impl Iterator<Item = u32>) -> Result<u32> {
        eflags
            .all_equal_value()
            .map_err(|_e| error!("non-unique e_flags"))
    }

    fn high_part_relocations() -> &'static [u32] {
        &[]
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
        let mut relocation = ElfLoongArch64::relocation_from_raw(relocation_kind).unwrap();
        let interposable = flags.is_interposable();

        // All relaxations below only apply to executable code, so we shouldn't attempt them if a
        // relocation is in a non-executable section.
        if !section_flags.contains(shf::EXECINSTR) {
            return None;
        }

        let offset = offset_in_section as usize;

        match relocation_kind {
            object::elf::R_LARCH_B26 if !interposable => {
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
                        rel_info: rel_info_from_type!(object::elf::R_LARCH_NONE),
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
