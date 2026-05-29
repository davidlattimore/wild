use crate::header_diff::Converter;
use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Ok;
use anyhow::Result;
use linker_utils::elf::pt;
use object::Object;
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

fn read_program_segment_fields(object: &crate::Binary) -> Result<FieldValues> {
    let e = object.file.endianness();
    let mut values = FieldValues::default();

    match object.file {
        object::File::Elf64(elf_file) => {
            for segment in elf_file.elf_program_headers() {
                let p_type = segment.p_type(e);
                let p_flags = segment.p_flags(e);
                let p_align = segment.p_align(e);

                if p_type == PT_LOAD {
                    let mut flag_str = String::new();
                    if p_flags.contains(object::elf::PF_R) {
                        flag_str.push('R');
                    }
                    if p_flags.contains(object::elf::PF_W) {
                        flag_str.push('W');
                    }
                    if p_flags.contains(object::elf::PF_X) {
                        flag_str.push('X');
                    }

                    values.insert(
                        format!("LOAD.{flag_str}.alignment"),
                        p_align,
                        Converter::None,
                        object,
                    );
                } else {
                    let segment_type = pt::Display(p_type);

                    values.insert(
                        format!("{segment_type}.alignment"),
                        p_align,
                        Converter::None,
                        object,
                    );
                    values.insert(
                        format!("{segment_type}.flags"),
                        p_flags.0,
                        Converter::None,
                        object,
                    );
                }
            }
        }
        _ => {}
    }

    Ok(values)
}
