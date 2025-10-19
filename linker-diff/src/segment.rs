use crate::header_diff::Converter;
use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Ok;
use anyhow::Result;
use linker_utils::elf::SegmentType;
use object::LittleEndian;
use object::elf::PT_LOAD;
use object::read::elf::ProgramHeader as _;

pub(crate) fn report_diffs(report: &mut crate::Report, objects: &[crate::Binary]) {
    report.add_diffs(crate::header_diff::diff_fields(
        objects,
        read_program_segment_fields,
        "segment",
        DiffMode::Normal,
    ));
}

#[allow(clippy::unnecessary_wraps)]
fn read_program_segment_fields(object: &crate::Binary) -> Result<FieldValues> {
    let e = LittleEndian;
    let mut values = FieldValues::default();

    for segment in object.elf_file.elf_program_headers() {
        let p_type = segment.p_type(e);
        let p_flags = segment.p_flags(e);
        let p_align = segment.p_align(e);

        if p_type == PT_LOAD {
            let mut flag_str = String::new();
            if p_flags & 4 != 0 {
                flag_str.push('R');
            }
            if p_flags & 2 != 0 {
                flag_str.push('W');
            }
            if p_flags & 1 != 0 {
                flag_str.push('X');
            }

            values.insert(
                format!("LOAD.{flag_str}.alignment"),
                p_align,
                Converter::None,
                object,
            );
        } else {
            let segment_type = SegmentType::from_u32(p_type);

            values.insert(
                format!("{segment_type}.alignment"),
                p_align,
                Converter::None,
                object,
            );
            values.insert(
                format!("{segment_type}.flags"),
                p_flags,
                Converter::None,
                object,
            );
        }
    }

    Ok(values)
}
