use crate::slice_from_all_bytes;
use crate::Config;
use crate::Diff;
use crate::DiffValues;
use crate::Object;
use crate::Report;
use crate::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context as _;
use itertools::Itertools;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::elf::shf;
use linker_utils::elf::SectionFlags;
#[allow(clippy::wildcard_imports)]
use object::elf::*;
use object::read::elf::Dyn;
use object::read::elf::ElfSection64;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;

#[derive(Clone, Copy)]
pub(crate) enum Converter {
    None,
    SectionAddress,
    DynStrOffset,
    SymAddress,
    SectionIndex,
    SectionFlags,
}

impl Converter {
    fn convert(self, value: u64, obj: &Object) -> String {
        self.try_convert(value, obj)
            .unwrap_or_else(|e| e.to_string())
    }

    fn try_convert(self, value: u64, obj: &Object) -> Result<String> {
        match self {
            Converter::None => Ok(format!("0x{value:x}")),
            Converter::SectionAddress => {
                // Find the first non-empty, section at that address. Only return an empty section if
                // there is no non-empty sections at that address.
                let mut empty_section_name = None;
                for section in obj.elf_file.sections() {
                    let object::SectionFlags::Elf { sh_flags } = section.flags() else {
                        unreachable!();
                    };
                    let section_flags = SectionFlags::from(sh_flags);
                    if section.address() == value && section_flags.contains(shf::ALLOC) {
                        if section.data().map(<[u8]>::len).unwrap_or(0) == 0 {
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
            Converter::DynStrOffset => {
                let dynstr = obj
                    .elf_file
                    .section_by_name(DYNSTR_SECTION_NAME_STR)
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
            Converter::SectionFlags => Ok(SectionFlags::from(value).to_string()),
        }
    }
}

fn symbol_with_address(obj: &Object, address: u64, allow_empty: bool) -> Option<String> {
    if address == 0 {
        return None;
    }
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
    report.add_diffs(diff_fields(
        objects,
        read_file_header_fields,
        "file-header",
        DiffMode::IgnoreIfAllErrors,
    ));
}

pub(crate) fn check_dynamic_headers(report: &mut Report, objects: &[crate::Object]) {
    report.add_diffs(diff_fields(
        objects,
        read_dynamic_fields,
        DYNAMIC_SECTION_NAME_STR,
        DiffMode::IgnoreIfAllErrors,
    ));
}

pub(crate) fn report_section_diffs(report: &mut Report, objects: &[Object]) {
    // Collect up the names of all sections in all objects. We ignore empty sections though, since
    // Wild will output empty sections if they have start/stop symbols that are referenced.
    let mut all_names: HashSet<&[u8]> = HashSet::new();
    for obj in objects {
        all_names.extend(
            obj.sections_by_name
                .iter()
                .filter_map(|(name, info)| (info.size > 0).then_some(name)),
        );
    }
    for name in all_names {
        let table_name = format!(
            "section{}{}",
            if name.starts_with(b".") { "" } else { "." },
            String::from_utf8_lossy(name)
        );
        report.add_diffs(diff_fields(
            objects,
            |object| {
                let section = section_or_equiv(object, name, &report.config)
                    .ok_or_else(|| anyhow!("Section missing"))?;
                let mut values = FieldValues::default();
                values.insert("alignment", section.align(), Converter::None, object);
                let section_header = section.elf_section_header();
                values.insert(
                    "link",
                    section_header.sh_link.get(LittleEndian),
                    Converter::SectionIndex,
                    object,
                );
                values.insert(
                    "flags",
                    section_header.sh_flags.get(LittleEndian),
                    Converter::SectionFlags,
                    object,
                );
                values.insert(
                    "type",
                    section_header.sh_type.get(LittleEndian),
                    Converter::None,
                    object,
                );
                values.insert(
                    "entsize",
                    section_header.sh_entsize.get(LittleEndian),
                    Converter::None,
                    object,
                );
                Ok(values)
            },
            &table_name,
            DiffMode::Normal,
        ));
    }
}

fn section_or_equiv<'data, 'file: 'data>(
    object: &'file Object<'data>,
    name: &[u8],
    config: &Config,
) -> Option<ElfSection64<'data, 'file, LittleEndian>> {
    if let Some(section) = object.section_by_name_bytes(name) {
        return Some(section);
    }
    for (a, b) in &config.equiv {
        if name == a.as_bytes() {
            if let Some(section) = object.section_by_name_bytes(b.as_bytes()) {
                return Some(section);
            }
        }
        if name == b.as_bytes() {
            if let Some(section) = object.section_by_name_bytes(a.as_bytes()) {
                return Some(section);
            }
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffMode {
    Normal,
    IgnoreIfAllErrors,
}

pub(crate) fn diff_fields(
    objects: &[Object<'_>],
    get_fields_fn: impl Fn(&Object<'_>) -> Result<FieldValues>,
    table_name: &str,
    diff_mode: DiffMode,
) -> Vec<Diff> {
    let field_values = objects.iter().map(get_fields_fn).collect_vec();
    if diff_mode == DiffMode::IgnoreIfAllErrors && field_values.iter().all(Result::is_err) {
        return vec![];
    }
    let mut ok = Vec::new();
    let mut errors = Vec::new();
    let mut has_errors = false;
    for d in field_values {
        match d {
            Ok(o) => {
                ok.push(o);
                errors.push("OK".to_owned());
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
        if ok.iter().skip(1).all(|o| o.values.get(k) != first) {
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
pub(crate) struct FieldValues {
    values: HashMap<Cow<'static, str>, Vec<String>>,
}

impl FieldValues {
    pub(crate) fn insert(
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

    pub(crate) fn insert_string_owned(&mut self, key: String, value: String) {
        self.values.entry(Cow::Owned(key)).or_default().push(value);
    }

    fn insert_string(&mut self, key: &'static str, value: String) {
        self.values
            .entry(Cow::Borrowed(key))
            .or_default()
            .push(value);
    }
}

#[allow(clippy::unnecessary_wraps)]
fn read_file_header_fields(obj: &Object) -> Result<FieldValues> {
    let mut values = FieldValues::default();
    let header = obj.elf_file.elf_header();
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
        .section_by_name(DYNAMIC_SECTION_NAME_STR)
        .with_context(|| format!("`{obj}` is missing .dynamic"))?;

    let mut values: HashMap<Cow<'static, str>, Vec<String>> = HashMap::new();
    let e = LittleEndian;

    let entries: &[object::elf::Dyn64<LittleEndian>] = slice_from_all_bytes(dynamic.data()?);
    let mut got_null = false;
    for entry in entries {
        let (tag_name, converter) = match entry.d_tag(e) as u32 {
            // Ignore DT_NULL. All linkers should emit at least one, but many emit more than one.
            DT_NULL => {
                got_null = true;
                continue;
            }
            DT_NEEDED => (Cow::Borrowed("DT_NEEDED"), Converter::DynStrOffset),
            DT_PLTRELSZ => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_PLTRELSZ"), Converter::None)
            }
            DT_PLTGOT => (Cow::Borrowed("DT_PLTGOT"), Converter::SectionAddress),
            DT_HASH => (Cow::Borrowed("DT_HASH"), Converter::None),
            DT_STRTAB => (Cow::Borrowed("DT_STRTAB"), Converter::SectionAddress),
            DT_SYMTAB => (Cow::Borrowed("DT_SYMTAB"), Converter::SectionAddress),
            DT_RELA => (Cow::Borrowed("DT_RELA"), Converter::SectionAddress),
            DT_RELASZ => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_RELASZ"), Converter::None)
            }
            DT_RELAENT => (Cow::Borrowed("DT_RELAENT"), Converter::None),
            DT_STRSZ => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_STRSZ"), Converter::None)
            }
            DT_SYMENT => (Cow::Borrowed("DT_SYMENT"), Converter::None),
            DT_INIT => (Cow::Borrowed("DT_INIT"), Converter::SectionAddress),
            DT_FINI => (Cow::Borrowed("DT_FINI"), Converter::SectionAddress),
            DT_SONAME => (Cow::Borrowed("DT_SONAME"), Converter::DynStrOffset),
            DT_RPATH => (Cow::Borrowed("DT_RPATH"), Converter::None),
            DT_SYMBOLIC => (Cow::Borrowed("DT_SYMBOLIC"), Converter::None),
            DT_REL => (Cow::Borrowed("DT_REL"), Converter::SectionAddress),
            DT_RELSZ => (Cow::Borrowed("DT_RELSZ"), Converter::None),
            DT_RELENT => (Cow::Borrowed("DT_RELENT"), Converter::None),
            DT_PLTREL => (Cow::Borrowed("DT_PLTREL"), Converter::None),
            DT_DEBUG => (Cow::Borrowed("DT_DEBUG"), Converter::None),
            DT_TEXTREL => (Cow::Borrowed("DT_TEXTREL"), Converter::SectionAddress),
            DT_JMPREL => (Cow::Borrowed("DT_JMPREL"), Converter::SectionAddress),
            DT_BIND_NOW => (Cow::Borrowed("DT_BIND_NOW"), Converter::None),
            DT_INIT_ARRAY => (Cow::Borrowed("DT_INIT_ARRAY"), Converter::SectionAddress),
            DT_FINI_ARRAY => (Cow::Borrowed("DT_FINI_ARRAY"), Converter::SectionAddress),
            DT_INIT_ARRAYSZ => (Cow::Borrowed("DT_INIT_ARRAYSZ"), Converter::None),
            DT_FINI_ARRAYSZ => (Cow::Borrowed("DT_FINI_ARRAYSZ"), Converter::None),
            DT_RUNPATH => (Cow::Borrowed("DT_RUNPATH"), Converter::DynStrOffset),
            DT_FLAGS => (Cow::Borrowed("DT_FLAGS"), Converter::None),
            DT_PREINIT_ARRAY => (Cow::Borrowed("DT_PREINIT_ARRAY"), Converter::None),
            DT_PREINIT_ARRAYSZ => (Cow::Borrowed("DT_PREINIT_ARRAYSZ"), Converter::None),
            DT_SYMTAB_SHNDX => (Cow::Borrowed("DT_SYMTAB_SHNDX"), Converter::None),
            DT_FLAGS_1 => (Cow::Borrowed("DT_FLAGS_1"), Converter::None),
            DT_RELACOUNT => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_RELACOUNT"), Converter::None)
            }
            DT_GNU_HASH => (Cow::Borrowed("DT_GNU_HASH"), Converter::SectionAddress),
            DT_VERSYM => (Cow::Borrowed("DT_VERSYM"), Converter::SectionAddress),
            DT_VERNEEDNUM => (Cow::Borrowed("DT_VERNEEDNUM"), Converter::None),
            DT_VERNEED => (Cow::Borrowed("DT_VERNEED"), Converter::SectionAddress),
            DT_LOOS => (Cow::Borrowed("DT_LOOS"), Converter::None),
            DT_HIOS => (Cow::Borrowed("DT_HIOS"), Converter::None),
            DT_LOPROC => (Cow::Borrowed("DT_LOPROC"), Converter::None),
            DT_HIPROC => (Cow::Borrowed("DT_HIPROC"), Converter::None),
            DT_VALRNGLO => (Cow::Borrowed("DT_VALRNGLO"), Converter::None),
            DT_GNU_PRELINKED => (Cow::Borrowed("DT_GNU_PRELINKED"), Converter::None),
            DT_GNU_CONFLICTSZ => (Cow::Borrowed("DT_GNU_CONFLICTSZ"), Converter::None),
            DT_GNU_LIBLISTSZ => (Cow::Borrowed("DT_GNU_LIBLISTSZ"), Converter::None),
            DT_CHECKSUM => (Cow::Borrowed("DT_CHECKSUM"), Converter::None),
            DT_PLTPADSZ => (Cow::Borrowed("DT_PLTPADSZ"), Converter::None),
            DT_MOVEENT => (Cow::Borrowed("DT_MOVEENT"), Converter::None),
            DT_MOVESZ => (Cow::Borrowed("DT_MOVESZ"), Converter::None),
            DT_FEATURE_1 => (Cow::Borrowed("DT_FEATURE_1"), Converter::None),
            DT_POSFLAG_1 => (Cow::Borrowed("DT_POSFLAG_1"), Converter::None),
            DT_SYMINSZ => (Cow::Borrowed("DT_SYMINSZ"), Converter::None),
            DT_SYMINENT => (Cow::Borrowed("DT_SYMINENT"), Converter::None),
            DT_ADDRRNGLO => (Cow::Borrowed("DT_ADDRRNGLO"), Converter::None),
            DT_TLSDESC_PLT => (Cow::Borrowed("DT_TLSDESC_PLT"), Converter::None),
            DT_TLSDESC_GOT => (Cow::Borrowed("DT_TLSDESC_GOT"), Converter::None),
            DT_GNU_CONFLICT => (Cow::Borrowed("DT_GNU_CONFLICT"), Converter::None),
            DT_GNU_LIBLIST => (Cow::Borrowed("DT_GNU_LIBLIST"), Converter::None),
            DT_CONFIG => (Cow::Borrowed("DT_CONFIG"), Converter::None),
            DT_DEPAUDIT => (Cow::Borrowed("DT_DEPAUDIT"), Converter::None),
            DT_AUDIT => (Cow::Borrowed("DT_AUDIT"), Converter::None),
            DT_PLTPAD => (Cow::Borrowed("DT_PLTPAD"), Converter::None),
            DT_MOVETAB => (Cow::Borrowed("DT_MOVETAB"), Converter::None),
            DT_SYMINFO => (Cow::Borrowed("DT_SYMINFO"), Converter::None),
            DT_RELCOUNT => (Cow::Borrowed("DT_RELCOUNT"), Converter::None),
            DT_VERDEF => (Cow::Borrowed("DT_VERDEF"), Converter::None),
            DT_VERDEFNUM => (Cow::Borrowed("DT_VERDEFNUM"), Converter::None),
            DT_AUXILIARY => (Cow::Borrowed("DT_AUXILIARY"), Converter::None),
            other => (
                Cow::Owned(format!("Unknown (0x{other:x})")),
                Converter::None,
            ),
        };
        if got_null {
            bail!("Found {tag_name} after DT_NULL");
        }
        values
            .entry(tag_name)
            .or_default()
            .push(converter.convert(entry.d_val(e), obj));
    }
    if !got_null {
        bail!("Missing DT_NULL entry");
    }

    Ok(FieldValues { values })
}
