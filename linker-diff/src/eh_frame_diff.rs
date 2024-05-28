use crate::Result;
use anyhow::bail;
use anyhow::Context;
use object::elf::ProgramHeader64;
use object::read::elf::ProgramHeader;
use object::LittleEndian;
use object::ObjectSection;

pub(crate) fn validate_eh_frame_hdr(object: &crate::Object) -> Result {
    let segment_hdr =
        eh_frame_segment(object).context("Missing program GNU_EH_FRAME program header")?;

    let section_hdr = object
        .section_by_name(".eh_frame_hdr")
        .context("Missing .eh_frame_hdr")?;

    let address1 = segment_hdr.p_vaddr(LittleEndian);
    let address2 = section_hdr.address();
    if address1 != address2 {
        bail!(".eh_frame_hdr address doesn't match GNU_EN_FRAME segment");
    }

    Ok(())
}

pub(crate) fn report_diffs(report: &mut crate::Report, objects: &[crate::Object]) {}

fn eh_frame_segment(object: &crate::Object) -> Option<ProgramHeader64<LittleEndian>> {
    for hdr in object.elf_file.elf_program_headers() {
        if hdr.p_type.get(LittleEndian) == object::elf::PT_GNU_EH_FRAME {
            return Some(*hdr);
        }
    }
    None
}

#[derive(Zeroable, Pod, Clone, Copy)]
#[repr(C)]
struct EhFrameHdr {
    pub(crate) version: u8,
    pub(crate) frame_pointer_encoding: u8,
    pub(crate) count_encoding: u8,
    pub(crate) table_encoding: u8,
    // For now we just use 32 bit pointer and count because it means that they're aligned. If we
    // need to upgrade these to u64, then we'd have to write these as unaligned fields.
    pub(crate) frame_pointer: i32,
    pub(crate) entry_count: u32,
}
