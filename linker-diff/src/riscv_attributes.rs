use crate::header_diff::DiffMode;
use crate::header_diff::FieldValues;
use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use linker_utils::elf::RISCV_ATTRIBUTE_VENDOR_NAME;
use linker_utils::elf::riscvattr::TAG_RISCV_ARCH;
use linker_utils::elf::riscvattr::TAG_RISCV_ATOMIC_ABI;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_MINOR;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_REVISION;
use linker_utils::elf::riscvattr::TAG_RISCV_STACK_ALIGN;
use linker_utils::elf::riscvattr::TAG_RISCV_UNALIGNED_ACCESS;
use linker_utils::elf::riscvattr::TAG_RISCV_WHOLE_FILE;
use linker_utils::elf::riscvattr::TAG_RISCV_X3_REG_USAGE;
use linker_utils::elf::secnames::RISCV_ATTRIBUTES_SECTION_NAME_STR;
use object::ObjectSection;
use std::collections::BTreeMap;
use std::ffi::CStr;

pub(crate) fn report_diffs(report: &mut crate::Report, objects: &[crate::Binary]) {
    report.add_diffs(crate::header_diff::diff_fields(
        objects,
        read_riscv_attributes_fields,
        "riscv_attributes",
        DiffMode::IgnoreIfAllErrors,
    ));
}

struct ParsedAttributes {
    attrs: BTreeMap<String, String>,
}

fn read_riscv_attributes_fields(object: &crate::Binary) -> Result<FieldValues> {
    let mut values = FieldValues::default();

    let Some(section) = object.section_by_name(RISCV_ATTRIBUTES_SECTION_NAME_STR) else {
        values.insert_string_owned(
            RISCV_ATTRIBUTES_SECTION_NAME_STR.to_owned(),
            "Missing".to_owned(),
        );

        return Ok(values);
    };

    let data = section.data()?;
    let parsed = parse_riscv_attributes(data)
        .context("Failed to parse .riscv.attributes section contents")?;

    for (key, value) in &parsed.attrs {
        values.insert_string_owned(key.clone(), value.clone());
    }

    Ok(values)
}

fn parse_riscv_attributes(data: &[u8]) -> Result<ParsedAttributes> {
    ensure!(!data.is_empty(), ".riscv.attributes section is empty");
    ensure!(
        data[0] == b'A',
        "Expected format version 'A', got 0x{:02x}",
        data[0]
    );

    let mut content = &data[1..];

    let _section_length = read_u32(&mut content).context("Cannot read section length")?;

    let vendor = read_string(&mut content).context("Cannot read vendor string")?;
    ensure!(
        vendor == RISCV_ATTRIBUTE_VENDOR_NAME,
        "Unsupported vendor '{vendor}', expected '{RISCV_ATTRIBUTE_VENDOR_NAME}'"
    );

    let content_at_subsection_start = content;
    let tag = read_uleb128(&mut content).context("Cannot read subsection tag")?;
    ensure!(
        tag == TAG_RISCV_WHOLE_FILE,
        "Expected TAG_FILE (1), got {tag}"
    );

    let subsection_length =
        read_u32(&mut content).context("Cannot read subsection length")? as usize;
    // subsection_length includes the tag and size field bytes we already consumed.
    let bytes_consumed = content_at_subsection_start.len() - content.len();
    let attribute_data_len = subsection_length
        .checked_sub(bytes_consumed)
        .with_context(|| {
            format!(
                "Subsection length ({subsection_length}) is smaller than header ({bytes_consumed})"
            )
        })?;
    ensure!(
        attribute_data_len <= content.len(),
        "Attribute data length ({attribute_data_len}) exceeds remaining data ({})",
        content.len()
    );
    let mut subsection_content = &content[..attribute_data_len];
    let mut attrs = BTreeMap::new();

    while !subsection_content.is_empty() {
        let tag = read_uleb128(&mut subsection_content).context("Cannot read attribute tag")?;
        match tag {
            TAG_RISCV_STACK_ALIGN => {
                let align = read_uleb128(&mut subsection_content)
                    .context("Cannot read stack alignment value")?;
                attrs.insert("stack_align".to_owned(), align.to_string());
            }
            TAG_RISCV_ARCH => {
                let arch_string = read_string(&mut subsection_content)
                    .context("Cannot read arch string value")?;
                let normalized = normalize_arch_string(&arch_string);
                attrs.insert("arch".to_owned(), normalized);
            }
            TAG_RISCV_UNALIGNED_ACCESS => {
                let access = read_uleb128(&mut subsection_content)
                    .context("Cannot read unaligned access value")?;
                attrs.insert(
                    "unaligned_access".to_owned(),
                    if access > 0 {
                        "allowed".to_owned()
                    } else {
                        "disallowed".to_owned()
                    },
                );
            }
            TAG_RISCV_PRIV_SPEC => {
                let version = read_uleb128(&mut subsection_content)
                    .context("Cannot read priv_spec major value")?;
                attrs.insert("priv_spec_major".to_owned(), version.to_string());
            }
            TAG_RISCV_PRIV_SPEC_MINOR => {
                let version = read_uleb128(&mut subsection_content)
                    .context("Cannot read priv_spec minor value")?;
                attrs.insert("priv_spec_minor".to_owned(), version.to_string());
            }
            TAG_RISCV_PRIV_SPEC_REVISION => {
                let version = read_uleb128(&mut subsection_content)
                    .context("Cannot read priv_spec revision value")?;
                attrs.insert("priv_spec_revision".to_owned(), version.to_string());
            }
            TAG_RISCV_ATOMIC_ABI => {
                let abi = read_uleb128(&mut subsection_content)
                    .context("Cannot read atomic ABI value")?;
                attrs.insert("atomic_abi".to_owned(), abi.to_string());
            }
            TAG_RISCV_X3_REG_USAGE => {
                let usage = read_uleb128(&mut subsection_content)
                    .context("Cannot read x3 register usage value")?;
                attrs.insert("x3_reg_usage".to_owned(), usage.to_string());
            }
            _ => {
                // Per the RISC-V ELF psABI, even-numbered tags have ULEB128 values and odd-numbered
                // tags have NTBS (null-terminated string) values.
                if tag % 2 == 0 {
                    let val = read_uleb128(&mut subsection_content)
                        .with_context(|| format!("Cannot read value for unknown tag {tag}"))?;
                    attrs.insert(format!("unknown_tag_{tag}"), val.to_string());
                } else {
                    let val = read_string(&mut subsection_content)
                        .with_context(|| format!("Cannot read value for unknown tag {tag}"))?;
                    attrs.insert(format!("unknown_tag_{tag}"), val);
                }
            }
        }
    }

    Ok(ParsedAttributes { attrs })
}

/// Sort extensions alphabetically.
fn normalize_arch_string(arch: &str) -> String {
    let parts: Vec<&str> = arch.split('_').collect();
    if parts.len() <= 1 {
        return arch.to_owned();
    }
    // The first part is the base ISA (e.g., "rv64i2p1").
    let base = parts[0];
    let mut extensions: Vec<&str> = parts[1..].to_vec();
    extensions.sort();
    let mut result = base.to_owned();
    for ext in extensions {
        result.push('_');
        result.push_str(ext);
    }

    result
}

fn read_uleb128(content: &mut &[u8]) -> Result<u64> {
    leb128::read::unsigned(content).context("Failed to read ULEB128 value")
}

fn read_string(content: &mut &[u8]) -> Result<String> {
    let cstr = CStr::from_bytes_until_nul(content).context("No null terminator found in string")?;
    let len = cstr.count_bytes() + 1; // include the null terminator
    let s = cstr.to_string_lossy().to_string();
    *content = &content[len..];
    Ok(s)
}

fn read_u32(content: &mut &[u8]) -> Result<u32> {
    ensure!(content.len() >= 4, "Not enough bytes to read u32");
    let value = u32::from_le_bytes(content[..4].try_into()?);
    *content = &content[4..];
    Ok(value)
}
