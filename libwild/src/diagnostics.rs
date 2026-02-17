use crate::elf::RawSymbolName;
use crate::grouping::SequencedInput;
use crate::input_data::FileId;
use crate::input_data::PRELUDE_FILE_ID;
use crate::platform::ObjectFile;
use crate::platform::RawSymbolName as _;
use crate::platform::Symbol as _;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::symbol::PreHashedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::value_flags::AtomicPerSymbolFlags;
use crate::value_flags::FlagsForSymbol as _;

/// Prints information about a symbol when dropped. We do this when dropped so that we can print
/// either after resolution flags have been computed, or, if layout gets an error, then before we
/// unwind.
pub(crate) struct SymbolInfoPrinter<'data, O: ObjectFile<'data>> {
    loaded_file_ids: hashbrown::HashSet<FileId>,
    symbol_db: &'data SymbolDb<'data, O>,
    name: &'data str,
    per_symbol_flags: &'data AtomicPerSymbolFlags<'data>,
}

impl<'data, O: ObjectFile<'data>> Drop for SymbolInfoPrinter<'data, O> {
    fn drop(&mut self) {
        self.print();
    }
}

impl<'data, O: ObjectFile<'data>> SymbolInfoPrinter<'data, O> {
    pub(crate) fn new(
        symbol_db: &'data SymbolDb<'data, O>,
        name: &'data str,
        flags: &'data AtomicPerSymbolFlags<'data>,
        groups: &[ResolvedGroup],
    ) -> Self {
        let loaded_file_ids = groups
            .iter()
            .flat_map(|group| {
                group.files.iter().filter_map(|file| match file {
                    ResolvedFile::NotLoaded(_) => None,
                    ResolvedFile::Prelude(_) => Some(PRELUDE_FILE_ID),
                    ResolvedFile::Object(obj) => Some(obj.common.file_id),
                    ResolvedFile::Dynamic(obj) => Some(obj.common.file_id),
                    ResolvedFile::LinkerScript(obj) => Some(obj.file_id),
                    ResolvedFile::SyntheticSymbols(obj) => Some(obj.file_id),
                    #[cfg(feature = "plugins")]
                    ResolvedFile::LtoInput(obj) => Some(obj.file_id),
                })
            })
            .collect();

        Self {
            loaded_file_ids,
            symbol_db,
            name,
            per_symbol_flags: flags,
        }
    }

    fn print(&self) {
        let name = self
            .symbol_db
            .find_mangled_name(self.name)
            .unwrap_or_else(|| self.name.to_owned());

        let matcher = NameMatcher::new(&name);
        let mut target_ids = Vec::new();
        target_ids.extend(name.parse().ok().map(SymbolId::from_usize));

        let symbol_id = self.symbol_db.get(
            &PreHashedSymbolName::from_raw(&RawSymbolName::parse(name.as_bytes())),
            true,
        );
        println!("Global name `{name}` refers to: {symbol_id:?}");

        target_ids.extend(symbol_id);

        println!("Definitions / references with name `{name}`:");
        for i in 0..self.symbol_db.num_symbols() {
            let symbol_id = SymbolId::from_usize(i);
            let canonical = self.symbol_db.definition(symbol_id);
            let file_id = self.symbol_db.file_id_for_symbol(symbol_id);
            let flags = self.per_symbol_flags.flags_for_symbol(symbol_id);

            let file_state = if self.loaded_file_ids.contains(&file_id) {
                "LOADED"
            } else {
                "NOT LOADED"
            };

            let Ok(sym_name) = self.symbol_db.symbol_name(symbol_id) else {
                continue;
            };

            let is_name_match = matcher.matches(sym_name.bytes(), symbol_id, self.symbol_db);

            let is_id_match = target_ids.contains(&symbol_id);

            if is_name_match || is_id_match {
                if symbol_id != canonical {
                    // Show info about the canonical symbol too. Generally the canonical symbol will
                    // have the same name, so this won't do anything. Note, this only works if the
                    // related symbol is later. Fixing that would require restructuring this
                    // function.
                    target_ids.push(canonical);
                }

                let file = self.symbol_db.file(file_id);
                let local_index = symbol_id.to_input(file.symbol_id_range());

                let sym_debug;
                let input;

                match file {
                    SequencedInput::Prelude(_) => {
                        input = "  <prelude>".to_owned();
                        sym_debug = "Prelude symbol".to_owned();
                    }
                    SequencedInput::Object(o) => match o.parsed.object.symbol(local_index) {
                        Ok(sym) => {
                            sym_debug = sym.debug_string();
                            input = o.parsed.input.to_string();
                        }
                        Err(e) => {
                            println!(
                                "  Corrupted input (file_id #{file_id}) {}: {}",
                                o.parsed.input,
                                e.to_string()
                            );
                            continue;
                        }
                    },
                    SequencedInput::LinkerScript(s) => {
                        sym_debug = "Linker script symbol".to_owned();
                        input = s.parsed.input.to_string();
                    }
                    SequencedInput::SyntheticSymbols(_) => {
                        input = "  <synthetic>".to_owned();
                        sym_debug = "Synthetic symbol".to_owned();
                    }
                    #[cfg(feature = "plugins")]
                    SequencedInput::LtoInput(o) => {
                        input = o.to_string();
                        sym_debug = o.symbol_properties_display(symbol_id).to_string();
                    }
                }

                // Versions can be either literally within the symbol name or in separate version
                // tables. It's useful to know which we've got, so if we get a version from a
                // separate table, we separate it visually from the rest of the name.
                let version_str = self
                    .symbol_db
                    .symbol_version_debug(symbol_id)
                    .map_or_else(String::new, |v| format!(" version `{v}`"));

                let canon = if symbol_id == canonical {
                    "".to_owned()
                } else {
                    format!(" -> {canonical}")
                };

                println!(
                    "  {symbol_id}{canon}: {sym_debug}: {flags} \
                            \n    {sym_name}{version_str}\n    \
                            #{local_index} in File #{file_id} {input} ({file_state})"
                );
            }
        }
    }
}

#[derive(Debug)]
struct NameMatcher {
    name: String,
    version: VersionMatcher,
}

#[derive(Debug)]
enum VersionMatcher {
    None,
    Exact(String),
    Any,
}

impl NameMatcher {
    fn new(pattern: &str) -> Self {
        if let Some((n, v)) = pattern.split_once('@') {
            Self {
                name: n.to_owned(),
                version: VersionMatcher::new(v),
            }
        } else {
            Self {
                name: pattern.to_owned(),
                version: VersionMatcher::None,
            }
        }
    }

    fn matches<'data, O: ObjectFile<'data>>(
        &self,
        name: &[u8],
        symbol_id: SymbolId,
        symbol_db: &SymbolDb<'data, O>,
    ) -> bool {
        if let Some(i) = name.iter().position(|b| *b == b'@') {
            let (name, version) = name.split_at(i);
            return name == self.name.as_bytes() && self.version.matches_at_prefixed(version);
        }

        if name != self.name.as_bytes() {
            return false;
        }

        self.version.matches_at_prefixed(
            symbol_db
                .symbol_version_debug(symbol_id)
                .unwrap_or_default()
                .as_bytes(),
        )
    }
}

impl VersionMatcher {
    fn new(n: &str) -> Self {
        if n == "*" {
            VersionMatcher::Any
        } else {
            VersionMatcher::Exact(n.to_owned())
        }
    }

    fn matches_at_prefixed(&self, mut version: &[u8]) -> bool {
        let is_default = version.starts_with(b"@@");
        while let Some(rest) = version.strip_prefix(b"@") {
            version = rest;
        }
        match self {
            VersionMatcher::Any => true,
            VersionMatcher::Exact(v) => version == v.as_bytes(),
            VersionMatcher::None => is_default || version.is_empty(),
        }
    }
}
