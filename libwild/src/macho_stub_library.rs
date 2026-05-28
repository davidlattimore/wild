//! Parser for the Text-Based Stub (`.tbd`) library definitions used by Mach-O.
//!
//! This crate currently targets TBD format version 4 and extracts the
//! linker-visible symbol definitions (and weak symbols). To keep parsing
//! simple and efficient, the parser rejects escape sequences and returns
//! `&'data str` slices directly from the input.
//!
//! The parser accepts multi-document YAML TBD files. The first document is
//! treated as the main library. Additional documents are treated as child
//! libraries reexported by the main library. This covers a practical subset of
//! the full TBD v4 format, including the shape used by most system libraries.

use crate::ensure;
use crate::error;
use crate::error::Result;
use itertools::Itertools;
use serde::Deserialize;
use std::collections::HashSet;

const ARM64_LIB_ARCH: &str = "arm64-macos";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct TextBasedDefinition<'a> {
    tbd_version: u32,
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    install_name: &'a str,
    #[serde(default)]
    current_version: &'a str,
    #[serde(default)]
    parent_umbrella: Vec<ParentUmbrella<'a>>,
    #[serde(default)]
    reexported_libraries: Vec<ReexportedLibraries<'a>>,
    #[serde(default)]
    exports: Vec<Exports<'a>>,
    #[serde(default)]
    reexports: Vec<Exports<'a>>,
}

impl<'a> TextBasedDefinition<'a> {
    fn all_exports(&self) -> impl Iterator<Item = &Exports<'a>> {
        self.exports.iter().chain(&self.reexports)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ParentUmbrella<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    umbrella: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ReexportedLibraries<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(borrow)]
    libraries: Vec<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Exports<'a> {
    #[serde(borrow)]
    targets: Vec<&'a str>,
    #[serde(default)]
    #[serde(borrow)]
    symbols: Vec<&'a str>,
    #[serde(default)]
    #[serde(borrow)]
    weak_symbols: Vec<&'a str>,
}
// TODO: remove
#[allow(unused)]
#[derive(Debug, Clone)]
pub(crate) struct DefinedStubLibrary<'a> {
    /// Install name of the dynamic library, including its `.dylib` suffix.    
    pub(crate) install_name: String,
    /// Current version recorded for the library, if present.
    pub(crate) current_version: String,
    /// Global symbols defined by the library or by any reexported child library.
    pub(crate) symbols: Vec<&'a str>,
    /// Weak symbols defined by the library or by any reexported child library.
    pub(crate) weak_symbols: Vec<&'a str>,
}

impl DefinedStubLibrary<'_> {
    pub(crate) fn total_symbols(&self) -> usize {
        self.symbols.len() + self.weak_symbols.len()
    }
}

pub fn parse_defined_library<'data>(input: &'data str) -> Result<DefinedStubLibrary<'data>> {
    let library_definitions = serde_yaml::Deserializer::from_str(input)
        .map(TextBasedDefinition::deserialize)
        .collect::<Result<Vec<_>, _>>()?;

    let main_library = library_definitions
        .first()
        .ok_or_else(|| error!("root library must be defined"))?;
    ensure!(
        main_library.targets.contains(&ARM64_LIB_ARCH),
        "'{ARM64_LIB_ARCH}' architecture not implemented by the library"
    );

    ensure!(
        !main_library.current_version.is_empty(),
        "Missing library version of the main library"
    );
    let mut defined_library = DefinedStubLibrary {
        install_name: main_library.install_name.to_string(),
        current_version: main_library.current_version.to_string(),
        symbols: Vec::with_capacity(
            library_definitions
                .iter()
                .flat_map(TextBasedDefinition::all_exports)
                .map(|exp| exp.symbols.len())
                .sum(),
        ),
        weak_symbols: Vec::with_capacity(
            library_definitions
                .iter()
                .flat_map(TextBasedDefinition::all_exports)
                .map(|exp| exp.weak_symbols.len())
                .sum(),
        ),
    };

    // Main libraries commonly reexport symbols from child libraries. This parser
    // currently supports only a flat tree: one main library with leaf children.
    let exported_libraries = if let Some(exported_libraries) = main_library
        .reexported_libraries
        .iter()
        .at_most_one()
        .map_err(|_| error!("expected just a single exported library"))?
    {
        ensure!(
            exported_libraries.targets.contains(&ARM64_LIB_ARCH),
            "'{ARM64_LIB_ARCH}' architecture not covered in the exported library"
        );
        let exported_libraries: HashSet<_> = exported_libraries.libraries.iter().copied().collect();
        exported_libraries
    } else {
        HashSet::new()
    };

    for lib in &library_definitions {
        ensure!(
            lib.tbd_version == 4,
            "TBD version 4 expected, got {}",
            lib.tbd_version
        );
        if lib != main_library {
            ensure!(
                exported_libraries.contains(lib.install_name),
                "child library '{}' not listed as reexported by the main library",
                lib.install_name
            );
        }

        for export in lib.all_exports() {
            if export.targets.contains(&ARM64_LIB_ARCH) {
                defined_library.symbols.extend(export.symbols.iter());
                defined_library
                    .weak_symbols
                    .extend(export.weak_symbols.iter());
            }
        }
    }

    Ok(defined_library)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_library_with_reexports() {
        let stub_library = parse_defined_library(
            r#"--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64-macos ]
install-name:    '/usr/lib/libMain.dylib'
current-version: 1.2.3
reexported-libraries:
  - targets:         [ x86_64-macos, arm64-macos ]
    libraries:       [ '/usr/lib/libA.dylib', '/usr/lib/libB.dylib' ]
exports:
  - targets:         [ arm64-macos ]
    symbols:         [ _main_arm64 ]
    weak-symbols:    [ _main_weak_arm64 ]
  - targets:         [ x86_64-macos ]
    symbols:         [ _main_x86_64 ]
    weak-symbols:    [ _main_weak_x86_64 ]
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64-macos ]
install-name:    '/usr/lib/libA.dylib'
current-version: 10
parent-umbrella:
  - targets:         [ x86_64-macos, arm64-macos ]
    umbrella:        Main
exports:
  - targets:         [ arm64-macos ]
    symbols:         [ _a_arm64 ]
    weak-symbols:    [ _a_weak_arm64 ]
  - targets:         [ x86_64-macos ]
    symbols:         [ _a_x86_64 ]
--- !tapi-tbd
tbd-version:     4
targets:         [ x86_64-macos, arm64-macos ]
install-name:    '/usr/lib/libB.dylib'
current-version: 11
parent-umbrella:
  - targets:         [ x86_64-macos, arm64-macos ]
    umbrella:        Main
exports:
  - targets:         [ arm64-macos ]
    symbols:         [ _b_arm64 ]
reexports:
  - targets:         [ arm64-macos ]
    symbols:         [ _b_exported_arm64 ]
    weak-symbols:    [ _b_weak_exported_arm64 ]
"#,
        )
        .expect("definition should parse");

        assert_eq!(stub_library.install_name, "/usr/lib/libMain.dylib");
        assert_eq!(stub_library.current_version, "1.2.3");
        assert_eq!(
            stub_library.symbols,
            ["_main_arm64", "_a_arm64", "_b_arm64", "_b_exported_arm64"]
        );
        assert_eq!(
            stub_library.weak_symbols,
            [
                "_main_weak_arm64",
                "_a_weak_arm64",
                "_b_weak_exported_arm64"
            ]
        );
    }
}
