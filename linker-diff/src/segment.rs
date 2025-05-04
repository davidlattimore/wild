use crate::header_diff::Converter;
use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Ok;
use anyhow::Result;
use object::LittleEndian;
use object::elf::PT_GNU_STACK;
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

        match p_type {
            PT_GNU_STACK => {
                values.insert("GNU_STACK.alignment", p_align, Converter::None, object);
                values.insert("GNU_STACK.flags", p_flags, Converter::None, object);
            }
            PT_LOAD => {
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

                let key = format!("LOAD.{flag_str}.alignment");
                values.insert(key, p_align, Converter::None, object);
            }
            _ => {}
        }
    }

    Ok(values)
}
