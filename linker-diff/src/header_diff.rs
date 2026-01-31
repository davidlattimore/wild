use crate::Binary;
use crate::Config;
use crate::Diff;
use crate::DiffValues;
use crate::Report;
use crate::Result;
use crate::slice_from_all_bytes;
use anyhow::Context as _;
use anyhow::anyhow;
use anyhow::bail;
use hashbrown::HashMap;
use hashbrown::HashSet;
use itertools::Itertools;
use linker_utils::elf::SectionFlags;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::elf::shf;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
#[allow(clippy::wildcard_imports)]
use object::elf::*;
use object::read::elf::Dyn;
use object::read::elf::ElfSection64;
use std::borrow::Cow;
use std::collections::BTreeSet;
use tabled::Table;
use tabled::settings::Style;
use tabled::settings::style::HorizontalLine;

#[derive(Clone, Copy)]
pub(crate) enum Converter {
    None,
    SectionAddress,
    DynStrOffset,
    SymAddress,
    SectionIndex,
    SectionFlags,
    BitFlags(&'static [Option<&'static str>]),
}

enum ConvertedValue {
    Single(String),
    Flags(Vec<String>),
}

impl Converter {
    fn insert_into(
        &self,
        key: Cow<'static, str>,
        value: u64,
        obj: &Binary<'_>,
        values_out: &mut FieldValues,
    ) {
        match self.try_convert(value, obj) {
            Ok(ConvertedValue::Single(converted)) => {
                values_out.values.entry(key).or_default().push(converted);
            }
            Ok(ConvertedValue::Flags(set_flags)) => {
                for name in set_flags {
                    values_out
                        .values
                        .entry(Cow::Owned(format!("{key}.{name}")))
                        .or_default()
                        .push("1".to_string());
                }
            }
            Err(error) => values_out
                .values
                .entry(key)
                .or_default()
                .push(error.to_string()),
        }
    }

    fn try_convert(self, value: u64, obj: &Binary) -> Result<ConvertedValue> {
        match self {
            Converter::None => Ok(ConvertedValue::Single(format!("0x{value:x}"))),
            Converter::SectionAddress => {
                // Find the first non-empty, section at that address. Only return an empty section
                // if there is no non-empty sections at that address.
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
                            return Ok(ConvertedValue::Single(section.name()?.to_owned()));
                        }
                    }
                }
                if let Some(name) = empty_section_name {
                    return Ok(ConvertedValue::Single(name));
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
                Ok(ConvertedValue::Single(
                    String::from_utf8_lossy(&rest[..len]).into_owned(),
                ))
            }
            Converter::SymAddress if value == 0 => Ok(ConvertedValue::Single("0x0".to_owned())),
            Converter::SymAddress => {
                // Find a symbol with the specified address. Give preference to symbols with
                // non-zero size.
                symbol_with_address(obj, value, false)
                    .or_else(|| symbol_with_address(obj, value, true))
                    .ok_or_else(|| anyhow!("No symbol at 0x{value:x}"))
                    .map(ConvertedValue::Single)
            }
            Converter::SectionIndex => Ok(ConvertedValue::Single(
                obj.elf_file
                    .section_by_index(object::SectionIndex(value as usize))?
                    .name()?
                    .to_owned(),
            )),
            Converter::SectionFlags => Ok(ConvertedValue::Single(
                SectionFlags::from(value).to_string(),
            )),
            Converter::BitFlags(items) => {
                let mut bits = value;
                let mut bit_names = items;
                let mut out = Vec::new();
                let mut bit_number = 0;
                while bits != 0 {
                    if bits & 1 != 0 {
                        out.push(
                            bit_names[0]
                                .map_or_else(|| format!("bit-{bit_number}"), |n| n.to_owned()),
                        );
                    }
                    bits >>= 1;
                    if !bit_names.is_empty() {
                        bit_names = &bit_names[1..];
                    }
                    bit_number += 1;
                }
                Ok(ConvertedValue::Flags(out))
            }
        }
    }
}

fn symbol_with_address(obj: &Binary, address: u64, allow_empty: bool) -> Option<String> {
    if address == 0 {
        return None;
    }

    for symbol_index in obj.address_index.symbols_at_address(address) {
        let sym = obj.elf_file.symbol_by_index(*symbol_index).ok()?;

        if !allow_empty && sym.size() == 0 {
            continue;
        }
        if sym.address() == address
            && let Ok(name) = sym.name()
            && !name.is_empty()
            && name != "$x"
        {
            return Some(name.to_owned());
        }
    }

    None
}

pub(crate) fn check_file_headers(report: &mut Report, objects: &[crate::Binary]) {
    report.add_diffs(diff_fields(
        objects,
        read_file_header_fields,
        "file-header",
        DiffMode::IgnoreIfAllErrors,
    ));
}

pub(crate) fn check_dynamic_headers(report: &mut Report, objects: &[crate::Binary]) {
    report.add_diffs(diff_fields(
        objects,
        read_dynamic_fields,
        DYNAMIC_SECTION_NAME_STR,
        DiffMode::IgnoreIfAllErrors,
    ));
}

pub(crate) fn report_section_diffs(report: &mut Report, objects: &[Binary]) {
    // Find section names defined by our first reference object. We ignore empty sections though,
    // since Wild will output empty sections if they have start/stop symbols that are referenced.
    let mut common_names: HashSet<&[u8]> = objects[1]
        .sections_by_name
        .iter()
        .filter_map(|(name, info)| (info.size > 0).then_some(*name))
        .collect();

    // Remove any section names that aren't also defined by our other reference objects. i.e. if any
    // of our reference objects don't define a section, then we won't compare that section.
    for obj in &objects[2..] {
        common_names.retain(|name| {
            obj.sections_by_name
                .get(*name)
                .is_some_and(|info| info.size > 0)
        });
    }

    for name in common_names {
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
    object: &'file Binary<'data>,
    name: &[u8],
    config: &Config,
) -> Option<ElfSection64<'data, 'file, LittleEndian>> {
    if let Some(section) = object.section_by_name_bytes(name) {
        return Some(section);
    }
    for (a, b) in &config.equiv {
        if name == a.as_bytes()
            && let Some(section) = object.section_by_name_bytes(b.as_bytes())
        {
            return Some(section);
        }
        if name == b.as_bytes()
            && let Some(section) = object.section_by_name_bytes(a.as_bytes())
        {
            return Some(section);
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiffMode {
    Normal,
    /// Do not error if getting values for a given pass fails for both sides. For example, when
    /// trying to compare section content, but neither side has it.
    IgnoreIfAllErrors,
    /// Do not error if the corresponding field value is missing on either side. For example, when
    /// diffing symbols in the section, but one side doesn't contain a corresponding symbol.
    IgnoreMissingValues,
}

pub(crate) fn diff_fields(
    objects: &[Binary<'_>],
    get_fields_fn: impl Fn(&Binary<'_>) -> Result<FieldValues>,
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
        if ok.iter().skip(1).all(|o| {
            let counterpart = o.values.get(k);
            if diff_mode == DiffMode::IgnoreMissingValues
                && (first.is_none() || counterpart.is_none())
            {
                return false;
            }
            counterpart != first
        }) {
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

pub(crate) fn diff_array(
    binaries: &[Binary<'_>],
    get_array_fn: impl Fn(&Binary<'_>) -> Result<Vec<ResolvedValue>>,
    table_name: &str,
) -> Vec<Diff> {
    let mut arrays = Vec::new();
    let mut errors = Vec::new();
    let mut has_errors = false;

    for bin in binaries {
        match get_array_fn(bin) {
            Ok(values) => {
                arrays.push(values);
                errors.push("OK".to_owned());
            }
            Err(err) => {
                errors.push(err.to_string());
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

    if all_equal(&arrays) {
        return vec![];
    }
    let mut rows = Vec::new();

    for values in arrays {
        for (i, value) in values.into_iter().enumerate() {
            if rows.len() <= i {
                rows.push(Vec::new());
            }
            rows[i].push(value.formatted);
        }
    }
    rows.insert(0, Vec::from_iter(binaries.iter().map(|b| b.name.clone())));

    let mut table = Table::from_iter(rows);
    table.with(
        Style::modern()
            .remove_horizontal()
            .horizontals([(1, HorizontalLine::inherit(Style::modern()))]),
    );

    vec![Diff {
        key: table_name.to_owned(),
        values: DiffValues::PreFormatted(table.to_string()),
    }]
}

pub(crate) struct ResolvedValue {
    /// This value is used when comparing for equality.
    pub(crate) for_comparison: String,

    /// This value is used for display purposes, but not for equality, so can include extra
    /// information like addresses that aren't expected to be equal.
    pub(crate) formatted: String,
}

impl PartialEq for ResolvedValue {
    fn eq(&self, other: &Self) -> bool {
        self.for_comparison == other.for_comparison
    }
}

fn all_equal(arrays: &[Vec<ResolvedValue>]) -> bool {
    let Some(first) = arrays.first() else {
        return true;
    };
    arrays[1..].iter().all(|a| a == first)
}

#[derive(Default)]
pub(crate) struct FieldValues {
    values: HashMap<Cow<'static, str>, Vec<String>>,
}

impl FieldValues {
    pub(crate) fn insert(
        &mut self,
        key: impl Into<Cow<'static, str>>,
        value: impl Into<u64>,
        converter: Converter,
        obj: &Binary,
    ) {
        let value = value.into();
        converter.insert_into(key.into(), value, obj, self);
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

    pub(crate) fn sort_values(&mut self) {
        for values in self.values.values_mut() {
            values.sort();
        }
    }
}

#[allow(clippy::unnecessary_wraps)]
fn read_file_header_fields(obj: &Binary) -> Result<FieldValues> {
    let mut values = FieldValues::default();
    let header = obj.elf_file.elf_header();
    let e = LittleEndian;
    values.insert_string("ident", format!("{:?}", header.e_ident.magic));
    values.insert("type", header.e_type.get(e), Converter::None, obj);
    values.insert("machine", header.e_machine.get(e), Converter::None, obj);
    values.insert("version", header.e_version.get(e), Converter::None, obj);
    values.insert("entry", header.e_entry.get(e), Converter::SymAddress, obj);
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

fn read_dynamic_fields(obj: &Binary) -> Result<FieldValues> {
    let dynamic = obj
        .section_by_name(DYNAMIC_SECTION_NAME_STR)
        .with_context(|| format!("`{obj}` is missing .dynamic"))?;

    let mut values = FieldValues::default();
    let e = LittleEndian;

    let entries: &[object::elf::Dyn64<LittleEndian>] = slice_from_all_bytes(dynamic.data()?);
    let mut got_null = false;

    // The following relies on the BFD order of the tags, but seems the easiest way how to catch
    // a situation where it emits RELA=0x, RELASZ=0, RELAENT=X.
    let mut rela_is_null = false;

    for entry in entries {
        let value = entry.d_val(e);
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
            DT_RELA => {
                if value == 0 {
                    rela_is_null = true;
                    continue;
                }
                (Cow::Borrowed("DT_RELA"), Converter::SectionAddress)
            }
            DT_RELASZ => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_RELASZ"), Converter::None)
            }
            DT_RELAENT => {
                if rela_is_null {
                    continue;
                }
                (Cow::Borrowed("DT_RELAENT"), Converter::None)
            }
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
            DT_PREINIT_ARRAY => (Cow::Borrowed("DT_PREINIT_ARRAY"), Converter::SectionAddress),
            DT_INIT_ARRAYSZ => (Cow::Borrowed("DT_INIT_ARRAYSZ"), Converter::None),
            DT_FINI_ARRAYSZ => (Cow::Borrowed("DT_FINI_ARRAYSZ"), Converter::None),
            DT_PREINIT_ARRAYSZ => (Cow::Borrowed("DT_PREINIT_ARRAYSZ"), Converter::None),
            DT_RUNPATH => (Cow::Borrowed("DT_RUNPATH"), Converter::DynStrOffset),
            DT_FLAGS => (
                Cow::Borrowed("DT_FLAGS"),
                Converter::BitFlags(&[
                    Some("ORIGIN"),
                    Some("SYMBOLIC"),
                    Some("TEXTREL"),
                    Some("BIND_NOW"),
                    Some("STATIC_TLS"),
                ]),
            ),

            DT_SYMTAB_SHNDX => (Cow::Borrowed("DT_SYMTAB_SHNDX"), Converter::None),
            DT_FLAGS_1 => (
                Cow::Borrowed("DT_FLAGS_1"),
                Converter::BitFlags(&[
                    Some("NOW"),
                    Some("GLOBAL"),
                    Some("GROUP"),
                    Some("NODELETE"),
                    Some("LOADFLTR"),
                    Some("INITFIRST"),
                    Some("NOOPEN"),
                    Some("ORIGIN"),
                    Some("DIRECT"),
                    Some("TRANS"),
                    Some("INTERPOSE"),
                    Some("NODEFLIB"),
                    Some("NODUMP"),
                    Some("CONFALT"),
                    Some("ENDFILTEE"),
                    Some("DISPRELDNE"),
                    Some("DISPRELPND"),
                    Some("NODIRECT"),
                    Some("IGNMULDEF"),
                    Some("NOKSYMS"),
                    Some("NOHDR"),
                    Some("EDITED"),
                    Some("NORELOC"),
                    Some("SYMINTPOSE"),
                    Some("GLOBAUDIT"),
                    Some("SINGLETON"),
                    Some("STUB"),
                    Some("PIE"),
                ]),
            ),
            DT_RELACOUNT => {
                // Ignore sizes for now.
                continue;
                //(Cow::Borrowed("DT_RELACOUNT"), Converter::None)
            }
            DT_GNU_HASH => (Cow::Borrowed("DT_GNU_HASH"), Converter::SectionAddress),
            DT_VERSYM => (Cow::Borrowed("DT_VERSYM"), Converter::SectionAddress),
            DT_VERDEF => (Cow::Borrowed("DT_VERDEF"), Converter::SectionAddress),
            DT_VERDEFNUM => (Cow::Borrowed("DT_VERDEFNUM"), Converter::None),
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
            DT_AUXILIARY => (Cow::Borrowed("DT_AUXILIARY"), Converter::DynStrOffset),
            other => (
                Cow::Owned(format!("Unknown (0x{other:x})")),
                Converter::None,
            ),
        };

        if got_null {
            bail!("Found {tag_name} after DT_NULL");
        }

        values.insert(tag_name, value, converter, obj);
    }

    if !got_null {
        bail!("Missing DT_NULL entry");
    }

    Ok(values)
}
