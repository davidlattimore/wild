//! PE/COFF linking pipeline.
//!
//! This is separate from the ELF pipeline because the Platform/ObjectFile traits are deeply
//! ELF-coupled. Shared abstractions can be extracted later once both pipelines work.

use crate::args::windows::PeArgs;
use crate::args::Args;
use crate::args::Input;
use crate::args::InputSpec;
use crate::bail;
use crate::coff::CoffFile;
use crate::error::Context as _;
use crate::error::Result;
use crate::file_kind::FileKind;
use crate::input_data::FileData;
use crate::input_data::InputFile;
use colosseum::sync::Arena;
use object::pe;
use std::path::Path;
use std::path::PathBuf;

pub(crate) fn link_pe<'data>(
    linker: &'data crate::Linker,
    args: &'data Args<PeArgs>,
) -> Result {
    let coff_files = load_coff_inputs(&linker.inputs_arena, args)?;

    let symbols = collect_symbols(&coff_files)?;

    eprintln!(
        "PE link: {} COFF objects, {} defined symbols, {} undefined symbols",
        coff_files.len(),
        symbols.defined.len(),
        symbols.undefined.len(),
    );

    bail!("PE layout and output writing not yet implemented");
}

struct SymbolInfo {
    /// Map from symbol name to (file index, value, section index).
    defined: hashbrown::HashMap<Vec<u8>, DefinedSymbol>,
    /// Symbols referenced but not defined.
    undefined: Vec<Vec<u8>>,
}

struct DefinedSymbol {
    file_index: usize,
    section_number: i32,
    value: u32,
}

fn load_coff_inputs<'data>(
    arena: &'data Arena<InputFile>,
    args: &'data Args<PeArgs>,
) -> Result<Vec<CoffFile<'data>>> {
    let mut coff_files = Vec::new();

    for input in &args.inputs {
        let path = resolve_pe_input(input, &args.lib_search_path)?;
        let file_data =
            FileData::new(&path, false).with_context(|| format!("Failed to open `{}`", path.display()))?;

        let input_file = arena.alloc(InputFile {
            filename: path.clone(),
            original_filename: path.clone(),
            modifiers: input.modifiers,
            data: Some(file_data),
        });
        let data = input_file.data();

        if data.is_empty() {
            continue;
        }

        let kind = FileKind::identify_bytes(data)
            .with_context(|| format!("Failed to identify `{}`", path.display()))?;

        match kind {
            FileKind::CoffObject => {
                let coff = CoffFile::parse(data)
                    .with_context(|| format!("Failed to parse COFF object `{}`", path.display()))?;
                coff_files.push(coff);
            }
            FileKind::CoffImport => {
                // TODO: Handle import libraries
            }
            FileKind::Archive => {
                load_archive_coff_objects(data, &path, arena, &mut coff_files)?;
            }
            FileKind::Text => {
                // Linker scripts — skip for now in PE mode
            }
            other => {
                bail!("Unsupported input file type `{other}` for PE linking: `{}`", path.display());
            }
        }
    }

    Ok(coff_files)
}

fn load_archive_coff_objects<'data>(
    archive_data: &'data [u8],
    archive_path: &Path,
    _arena: &'data Arena<InputFile>,
    coff_files: &mut Vec<CoffFile<'data>>,
) -> Result {
    let archive = object::read::archive::ArchiveFile::parse(archive_data)
        .with_context(|| format!("Failed to parse archive `{}`", archive_path.display()))?;

    for member in archive.members() {
        let member = member
            .with_context(|| format!("Failed to read archive member in `{}`", archive_path.display()))?;
        let member_data = member.data(archive_data)
            .with_context(|| format!("Failed to read archive member data in `{}`", archive_path.display()))?;

        if member_data.is_empty() {
            continue;
        }

        // Try to identify — skip non-COFF entries (e.g. import library headers)
        if let Ok(kind) = FileKind::identify_bytes(member_data) {
            match kind {
                FileKind::CoffObject => {
                    let coff = CoffFile::parse(member_data).with_context(|| {
                        format!(
                            "Failed to parse COFF object in archive `{}`",
                            archive_path.display()
                        )
                    })?;
                    coff_files.push(coff);
                }
                FileKind::CoffImport => {
                    // TODO: Handle import library entries
                }
                _ => {
                    // Skip other types in archives
                }
            }
        }
    }

    Ok(())
}

fn collect_symbols(coff_files: &[CoffFile]) -> Result<SymbolInfo> {
    let mut defined = hashbrown::HashMap::new();
    let mut undefined_set = hashbrown::HashSet::new();

    for (file_index, coff) in coff_files.iter().enumerate() {
        coff.for_each_symbol(|name, section_number, storage_class, value| {
            if storage_class == pe::IMAGE_SYM_CLASS_EXTERNAL {
                if section_number > 0 {
                    // Defined external symbol
                    defined.entry(name.to_vec()).or_insert(DefinedSymbol {
                        file_index,
                        section_number,
                        value,
                    });
                } else if section_number == 0 && value == 0 {
                    // Undefined external symbol
                    undefined_set.insert(name.to_vec());
                }
            }
            Ok(())
        })?;
    }

    // Remove symbols that are actually defined from the undefined set
    for key in defined.keys() {
        undefined_set.remove(key);
    }

    Ok(SymbolInfo {
        defined,
        undefined: undefined_set.into_iter().collect(),
    })
}

fn resolve_pe_input(input: &Input, lib_search_path: &[Box<Path>]) -> Result<PathBuf> {
    match &input.spec {
        InputSpec::File(p) => {
            let path = p.as_ref().to_owned();
            if path.exists() {
                Ok(path)
            } else if let Some(search_first) = &input.search_first {
                let searched = search_first.join(&path);
                if searched.exists() {
                    return Ok(searched);
                }
                Ok(path)
            } else {
                Ok(path)
            }
        }
        InputSpec::Lib(lib_name) => {
            // On Windows, search for <name>.lib
            let filename = format!("{lib_name}.lib");
            for dir in lib_search_path {
                let path = dir.join(&filename);
                if path.exists() {
                    return Ok(path);
                }
            }
            bail!("Couldn't find library `{lib_name}` on library search path");
        }
        InputSpec::Search(filename) => {
            for dir in lib_search_path {
                let path = dir.join(filename.as_ref());
                if path.exists() {
                    return Ok(path);
                }
            }
            bail!("Couldn't find `{filename}` on library search path");
        }
    }
}
