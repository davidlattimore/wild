use crate::grouping::SequencedInput;
use crate::input_data::FileId;
use crate::input_data::PRELUDE_FILE_ID;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::symbol::PreHashedSymbolName;
use crate::symbol_db::RawSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolId;
use crate::value_flags::AtomicPerSymbolFlags;
use crate::value_flags::FlagsForSymbol as _;

/// Prints information about a symbol when dropped. We do this when dropped so that we can print
/// either after resolution flags have been computed, or, if layout gets an error, then before we
/// unwind.
pub(crate) struct SymbolInfoPrinter<'data> {
    loaded_file_ids: hashbrown::HashSet<FileId>,
    symbol_db: &'data SymbolDb<'data>,
    name: &'data str,
    per_symbol_flags: &'data AtomicPerSymbolFlags<'data>,
}

impl Drop for SymbolInfoPrinter<'_> {
    fn drop(&mut self) {
        self.print();
    }
}

impl<'data> SymbolInfoPrinter<'data> {
    pub(crate) fn new(
        symbol_db: &'data SymbolDb,
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

        let versioned_prefix = if name.contains("@") {
            name.clone()
        } else {
            format!("{name}@")
        };

        let symbol_id = self.symbol_db.get(
            &PreHashedSymbolName::from_raw(&RawSymbolName::parse(name.as_bytes())),
            true,
        );
        println!("Global name `{name}` refers to: {symbol_id:?}",);

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

            if let Ok(sym_name) = self.symbol_db.symbol_name(symbol_id)
                && (sym_name.bytes() == name.as_bytes()
                    || sym_name.bytes().starts_with(versioned_prefix.as_bytes()))
            {
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
                            sym_debug = crate::symbol::SymDebug(sym).to_string();
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
                }

                // Versions can be either literally within the symbol name or in separate version
                // tables. It's useful to know which we've got, so if we get a version from a
                // separate table, we separate it visually from the rest of the name.
                let version_str = self
                    .symbol_db
                    .symbol_version_debug(symbol_id)
                    .map_or_else(String::new, |v| format!(" version `{v}`"));

                println!(
                    "  {sym_debug}: symbol_id={symbol_id} -> {canonical} {flags} \
                            \n    {sym_name}{version_str}\n    \
                            #{local_index} in File #{file_id} {input} ({file_state})"
                );
            }
        }
    }
}
