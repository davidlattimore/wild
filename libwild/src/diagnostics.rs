use crate::Args;
use crate::elf::RawSymbolName;
use crate::grouping::SequencedInput;
use crate::input_data::FileId;
use crate::input_data::PRELUDE_FILE_ID;
use crate::platform::ObjectFile;
use crate::platform::Platform;
use crate::platform::RawSymbolName as _;
use crate::platform::Symbol as _;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::symbol::PreHashedSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::value_flags::AtomicPerSymbolFlags;
use crate::value_flags::FlagsForSymbol as _;
use std::fmt::Write as _;

/// Prints information about a symbol when dropped. We do this when dropped so that we can print
/// either after resolution flags have been computed, or, if layout gets an error, then before we
/// unwind.
pub(crate) enum SymbolInfoPrinter {
    Disabled,
    Enabled(Box<State>),
}

pub(crate) struct State {
    loaded_file_ids: hashbrown::HashSet<FileId>,
    name: String,

    /// Our output the last time `update` was called. This is what will be printed when dropped
    /// unless `update` is called again.
    output: String,
}

impl Drop for SymbolInfoPrinter {
    fn drop(&mut self) {
        self.print();
    }
}

impl SymbolInfoPrinter {
    pub(crate) fn new<'data, P: Platform>(args: &Args, groups: &[ResolvedGroup<'data, P>]) -> Self {
        let Some(name) = args.sym_info.as_ref() else {
            return Self::Disabled;
        };

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

        Self::Enabled(Box::new(State {
            loaded_file_ids,
            name: name.to_owned(),
            output: "SymbolInfoPrinter::update never called, so can't print symbol info".into(),
        }))
    }

    pub(crate) fn update<'data, P: Platform>(
        &mut self,
        symbol_db: &SymbolDb<'data, P>,
        per_symbol_flags: &AtomicPerSymbolFlags<'_>,
    ) {
        let Self::Enabled(state) = self else {
            return;
        };

        let mut out = &mut state.output;
        out.clear();

        let name = symbol_db
            .find_mangled_name(&state.name)
            .unwrap_or_else(|| state.name.clone());

        let matcher = NameMatcher::new(&name);
        let mut target_ids = Vec::new();
        target_ids.extend(name.parse().ok().map(SymbolId::from_usize));

        let symbol_id = symbol_db.get(
            &PreHashedSymbolName::from_raw(&RawSymbolName::parse(name.as_bytes())),
            true,
        );
        let _ = writeln!(&mut out, "Global name `{name}` refers to: {symbol_id:?}");

        target_ids.extend(symbol_id);

        let _ = writeln!(&mut out, "Definitions / references with name `{name}`:");
        for i in 0..symbol_db.num_symbols() {
            let symbol_id = SymbolId::from_usize(i);
            let canonical = symbol_db.definition(symbol_id);
            let file_id = symbol_db.file_id_for_symbol(symbol_id);
            let flags = per_symbol_flags.flags_for_symbol(symbol_id);

            let file_state = if state.loaded_file_ids.contains(&file_id) {
                "LOADED"
            } else {
                "NOT LOADED"
            };

            let Ok(sym_name) = symbol_db.symbol_name(symbol_id) else {
                continue;
            };

            let is_name_match = matcher.matches(sym_name.bytes(), symbol_id, symbol_db);

            let is_id_match = target_ids.contains(&symbol_id);

            if is_name_match || is_id_match {
                if symbol_id != canonical {
                    // Show info about the canonical symbol too. Generally the canonical symbol will
                    // have the same name, so this won't do anything. Note, this only works if the
                    // related symbol is later. Fixing that would require restructuring this
                    // function.
                    target_ids.push(canonical);
                }

                let file = symbol_db.file(file_id);
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
                            let _ = writeln!(
                                &mut out,
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
                let version_str = symbol_db
                    .symbol_version_debug(symbol_id)
                    .map_or_else(String::new, |v| format!(" version `{v}`"));

                let canon = if symbol_id == canonical {
                    "".to_owned()
                } else {
                    format!(" -> {canonical}")
                };

                let _ = writeln!(
                    &mut out,
                    "  {symbol_id}{canon}: {sym_debug}: {flags} \
                            \n    {sym_name}{version_str}\n    \
                            #{local_index} in File #{file_id} {input} ({file_state})"
                );
            }
        }
    }

    fn print(&self) {
        match self {
            SymbolInfoPrinter::Disabled => {}
            SymbolInfoPrinter::Enabled(state) => {
                println!("{}", &state.output);
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

    fn matches<'data, P: Platform>(
        &self,
        name: &[u8],
        symbol_id: SymbolId,
        symbol_db: &SymbolDb<'data, P>,
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
