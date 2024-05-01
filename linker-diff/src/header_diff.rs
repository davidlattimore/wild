use crate::slice_from_all_bytes;
use crate::Diff;
use crate::DiffValues;
use crate::Object;
use crate::Report;
use crate::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context as _;
use object::read::elf::Dyn;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::SectionFlags;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::collections::HashMap;

enum Converter {
    None,
    SectionAddress,
    DynSymOffset,
    SymAddress,
    SectionIndex,
}

impl Converter {
    fn convert(&self, value: u64, obj: &Object) -> String {
        self.try_convert(value, obj)
            .unwrap_or_else(|e| e.to_string())
    }

    fn try_convert(&self, value: u64, obj: &Object) -> Result<String> {
        match self {
            Converter::None => Ok(format!("0x{value:x}")),
            Converter::SectionAddress => {
                // Find the first non-empty, section at that address. Only return an empty section if
                // there is no non-empty sections at that address.
                let mut empty_section_name = None;
                for section in obj.elf_file.sections() {
                    let SectionFlags::Elf { sh_flags } = section.flags() else {
                        unreachable!();
                    };
                    if section.address() == value && (sh_flags & object::elf::SHF_ALLOC as u64) != 0
                    {
                        if section.data().map(|d| d.len()).unwrap_or(0) == 0 {
                            empty_section_name = Some(section.name()?.to_owned());
                        } else {
                            return Ok(section.name()?.to_owned());
                        }
                    }
                }
                if let Some(name) = empty_section_name {
                    return Ok(name);
                }
                bail!("No section at 0x{value:x}");
            }
            Converter::DynSymOffset => {
                let dynstr = obj
                    .elf_file
                    .section_by_name(".dynstr")
                    .context("Missing .dynstr")?;
                let data = dynstr.data()?;
                let start = value as usize;
                if start >= data.len() {
                    bail!("Invalid .dynstr offset 0x{start:x}");
                }
                let rest = &data[start..];
                let len = rest.iter().position(|b| *b == 0).unwrap_or(0);
                Ok(String::from_utf8_lossy(&rest[..len]).into_owned())
            }
            Converter::SymAddress => {
                // Find a symbol with the specified address. Give preference to symbols with
                // non-zero size.
                symbol_with_address(obj, value, false)
                    .or_else(|| symbol_with_address(obj, value, true))
                    .ok_or_else(|| anyhow!("No symbol at 0x{value:x}"))
            }
            Converter::SectionIndex => Ok(obj
                .elf_file
                .section_by_index(object::SectionIndex(value as usize))?
                .name()?
                .to_owned()),
        }
    }
}

fn symbol_with_address(obj: &Object, address: u64, allow_empty: bool) -> Option<String> {
    // If we want this to be faster, we could build an index ahead of time.
    for sym in obj.elf_file.symbols() {
        if !allow_empty && sym.size() == 0 {
            continue;
        }
        if sym.address() == address {
            if let Ok(name) = sym.name() {
                if !name.is_empty() {
                    return Some(name.to_owned());
                }
            }
        }
    }
    None
}

pub(crate) fn check_file_headers(report: &mut Report, objects: &[crate::Object]) {
    report.add_diffs(diff_fields(objects, read_file_header_fields, "file-header"))
}

pub(crate) fn check_dynamic_headers(report: &mut Report, objects: &[crate::Object]) {
    report.add_diffs(diff_fields(objects, read_dynamic_fields, ".dynamic"));
}

fn diff_fields(
    objects: &[Object<'_>],
    get_fields_fn: fn(&Object<'_>) -> Result<FieldValues>,
    table_name: &'static str,
) -> Vec<Diff> {
    let dynamic_objects = objects
        .iter()
        .map(get_fields_fn)
        .collect::<Vec<Result<FieldValues>>>();
    if dynamic_objects.iter().all(|d| d.is_err()) {
        // All errors, so we're probably not expected to have a .dynamic section for this file.
        return vec![];
    }
    let mut ok = Vec::new();
    let mut errors = Vec::new();
    let mut has_errors = false;
    for d in dynamic_objects {
        match d {
            Ok(o) => {
                ok.push(o);
                errors.push("OK".to_owned())
            }
            Err(e) => {
                errors.push(e.to_string());
                has_errors = true;
            }
        }
    }
    if has_errors {
        return vec![Diff {
            key: table_name.to_owned(),
            values: DiffValues::PerObject(errors),
        }];
    }
    let mut all_keys = BTreeSet::new();
    for o in &ok {
        all_keys.extend(o.values.keys());
    }
    let mut mismatches = Vec::new();
    for k in all_keys {
        let first = ok.first().and_then(|o| o.values.get(k));
        if !ok.iter().all(|o| o.values.get(k) == first) {
            let values = ok
                .iter()
                .map(|o| o.values.get(k).map(|v| v.join(",")).unwrap_or_default())
                .collect();
            mismatches.push(Diff {
                key: format!("{table_name}.{k}"),
                values: DiffValues::PerObject(values),
            });
        }
    }
    mismatches
}

#[derive(Default)]
struct FieldValues {
    values: HashMap<Cow<'static, str>, Vec<String>>,
}

impl FieldValues {
    fn insert(
        &mut self,
        key: &'static str,
        value: impl Into<u64>,
        converter: Converter,
        obj: &Object,
    ) {
        let value = value.into();
        self.values
            .entry(Cow::Borrowed(key))
            .or_default()
            .push(converter.convert(value, obj));
    }

    fn insert_string(&mut self, key: &'static str, value: String) {
        self.values
            .entry(Cow::Borrowed(key))
            .or_default()
            .push(value);
    }
}

fn read_file_header_fields(obj: &Object) -> Result<FieldValues> {
    let mut values = FieldValues::default();
    let header = obj.elf_file.raw_header();
    let e = LittleEndian;
    values.insert_string("ident", format!("{:?}", header.e_ident.magic));
    values.insert("type", header.e_type.get(e), Converter::None, obj);
    values.insert("machine", header.e_machine.get(e), Converter::None, obj);
    values.insert("version", header.e_version.get(e), Converter::None, obj);
    if obj.has_symbols() {
        values.insert("entry", header.e_entry.get(e), Converter::SymAddress, obj);
    }
    values.insert("phoff", header.e_phoff.get(e), Converter::None, obj);
    values.insert("flags", header.e_flags.get(e), Converter::None, obj);
    values.insert("ehsize", header.e_ehsize.get(e), Converter::None, obj);
    values.insert("phentsize", header.e_phentsize.get(e), Converter::None, obj);
    values.insert("shentsize", header.e_shentsize.get(e), Converter::None, obj);
    values.insert(
        "shstrndx",
        header.e_shstrndx.get(e),
        Converter::SectionIndex,
        obj,
    );
    // We currently ignore e_shoff, e_phnum and e_shnum, since we don't really expect them the same
    // number of sections and program segments and the section header offset is also generally going
    // to be different between different linkers.
    Ok(values)
}

fn read_dynamic_fields(obj: &Object) -> Result<FieldValues> {
    let dynamic = obj
        .elf_file
        .section_by_name(".dynamic")
        .with_context(|| format!("`{obj}` is missing .dynamic"))?;

    let mut values: HashMap<Cow<'static, str>, Vec<String>> = HashMap::new();
    let e = LittleEndian;

    let entries: &[object::elf::Dyn64<LittleEndian>] = slice_from_all_bytes(dynamic.data()?);
    for entry in entries {
        let (tag_name, converter) = match entry.d_tag(e) {
            // Ignore DT_NULL. All linkers should emit at least one, but many emit more than one.
            0 => continue,
            1 => (Cow::Borrowed("DT_NEEDED"), Converter::DynSymOffset),
            2 => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_PLTRELSZ"), Converter::None)
            }
            3 => (Cow::Borrowed("DT_PLTGOT"), Converter::SectionAddress),
            4 => (Cow::Borrowed("DT_HASH"), Converter::None),
            5 => (Cow::Borrowed("DT_STRTAB"), Converter::SectionAddress),
            6 => (Cow::Borrowed("DT_SYMTAB"), Converter::SectionAddress),
            7 => (Cow::Borrowed("DT_RELA"), Converter::SectionAddress),
            8 => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_RELASZ"), Converter::None)
            }
            9 => (Cow::Borrowed("DT_RELAENT"), Converter::None),
            10 => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_STRSZ"), Converter::None)
            }
            11 => (Cow::Borrowed("DT_SYMENT"), Converter::None),
            12 => (Cow::Borrowed("DT_INIT"), Converter::SectionAddress),
            13 => (Cow::Borrowed("DT_FINI"), Converter::SectionAddress),
            14 => (Cow::Borrowed("DT_SONAME"), Converter::None),
            15 => (Cow::Borrowed("DT_RPATH"), Converter::None),
            16 => (Cow::Borrowed("DT_SYMBOLIC"), Converter::None),
            17 => (Cow::Borrowed("DT_REL"), Converter::SectionAddress),
            18 => (Cow::Borrowed("DT_RELSZ"), Converter::None),
            19 => (Cow::Borrowed("DT_RELENT"), Converter::None),
            20 => (Cow::Borrowed("DT_PLTREL"), Converter::None),
            21 => (Cow::Borrowed("DT_DEBUG"), Converter::None),
            22 => (Cow::Borrowed("DT_TEXTREL"), Converter::SectionAddress),
            23 => (Cow::Borrowed("DT_JMPREL"), Converter::SectionAddress),
            24 => (Cow::Borrowed("DT_BIND_NOW"), Converter::None),
            25 => (Cow::Borrowed("DT_INIT_ARRAY"), Converter::SectionAddress),
            26 => (Cow::Borrowed("DT_FINI_ARRAY"), Converter::SectionAddress),
            27 => (Cow::Borrowed("DT_INIT_ARRAYSZ"), Converter::None),
            28 => (Cow::Borrowed("DT_FINI_ARRAYSZ"), Converter::None),
            29 => (Cow::Borrowed("DT_RUNPATH"), Converter::None),
            30 => (Cow::Borrowed("DT_FLAGS"), Converter::None),
            32 => (Cow::Borrowed("DT_PREINIT_ARRAY"), Converter::None),
            33 => (Cow::Borrowed("DT_PREINIT_ARRAYSZ"), Converter::None),
            34 => (Cow::Borrowed("DT_SYMTAB_SHNDX"), Converter::None),
            0x6ffffffb => (Cow::Borrowed("DT_FLAGS_1"), Converter::None),
            0x6ffffff9 => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_RELACOUNT"), Converter::None)
            }
            0x6ffffef5 => (Cow::Borrowed("DT_GNU_HASH"), Converter::SectionAddress),
            0x6ffffff0 => (Cow::Borrowed("DT_VERSYM"), Converter::SectionAddress),
            0x6fffffff => (Cow::Borrowed("DT_VERNEEDNUM"), Converter::None),
            0x6ffffffe => (Cow::Borrowed("DT_VERNEED"), Converter::SectionAddress),
            0x6000_000d => (Cow::Borrowed("DT_LOOS"), Converter::None),
            0x6fff_f000 => (Cow::Borrowed("DT_HIOS"), Converter::None),
            0x7000_0000 => (Cow::Borrowed("DT_LOPROC"), Converter::None),
            0x7fff_ffff => (Cow::Borrowed("DT_HIPROC"), Converter::None),
            0x6fff_fd00 => (Cow::Borrowed("DT_VALRNGLO"), Converter::None),
            0x6fff_fdf5 => (Cow::Borrowed("DT_GNU_PRELINKED"), Converter::None),
            0x6fff_fdf6 => (Cow::Borrowed("DT_GNU_CONFLICTSZ"), Converter::None),
            0x6fff_fdf7 => (Cow::Borrowed("DT_GNU_LIBLISTSZ"), Converter::None),
            0x6fff_fdf8 => (Cow::Borrowed("DT_CHECKSUM"), Converter::None),
            0x6fff_fdf9 => (Cow::Borrowed("DT_PLTPADSZ"), Converter::None),
            0x6fff_fdfa => (Cow::Borrowed("DT_MOVEENT"), Converter::None),
            0x6fff_fdfb => (Cow::Borrowed("DT_MOVESZ"), Converter::None),
            0x6fff_fdfc => (Cow::Borrowed("DT_FEATURE_1"), Converter::None),
            0x6fff_fdfd => (Cow::Borrowed("DT_POSFLAG_1"), Converter::None),
            0x6fff_fdfe => (Cow::Borrowed("DT_SYMINSZ"), Converter::None),
            0x6fff_fdff => (Cow::Borrowed("DT_SYMINENT"), Converter::None),
            0x6fff_fe00 => (Cow::Borrowed("DT_ADDRRNGLO"), Converter::None),
            0x6fff_fef6 => (Cow::Borrowed("DT_TLSDESC_PLT"), Converter::None),
            0x6fff_fef7 => (Cow::Borrowed("DT_TLSDESC_GOT"), Converter::None),
            0x6fff_fef8 => (Cow::Borrowed("DT_GNU_CONFLICT"), Converter::None),
            0x6fff_fef9 => (Cow::Borrowed("DT_GNU_LIBLIST"), Converter::None),
            0x6fff_fefa => (Cow::Borrowed("DT_CONFIG"), Converter::None),
            0x6fff_fefb => (Cow::Borrowed("DT_DEPAUDIT"), Converter::None),
            0x6fff_fefc => (Cow::Borrowed("DT_AUDIT"), Converter::None),
            0x6fff_fefd => (Cow::Borrowed("DT_PLTPAD"), Converter::None),
            0x6fff_fefe => (Cow::Borrowed("DT_MOVETAB"), Converter::None),
            0x6fff_feff => (Cow::Borrowed("DT_SYMINFO"), Converter::None),
            0x6fff_fffa => (Cow::Borrowed("DT_RELCOUNT"), Converter::None),
            0x6fff_fffc => (Cow::Borrowed("DT_VERDEF"), Converter::None),
            0x6fff_fffd => (Cow::Borrowed("DT_VERDEFNUM"), Converter::None),
            0x7fff_fffd => (Cow::Borrowed("DT_AUXILIARY"), Converter::None),
            other => (
                Cow::Owned(format!("Unknown (0x{other:x})")),
                Converter::None,
            ),
        };
        values
            .entry(tag_name)
            .or_default()
            .push(converter.convert(entry.d_val(e), obj));
    }

    Ok(FieldValues { values })
}
