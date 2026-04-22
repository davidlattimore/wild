use crate::LinkerKind;
use crate::Result;
use anyhow::Context as _;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Deserialize, Serialize, Debug, Default, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) name: String,

    #[serde(default, rename = "bench")]
    pub(crate) benches: BTreeMap<String, BenchConfig>,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BenchConfig {
    #[serde(default)]
    pub(crate) skip: bool,
    pub(crate) min_wild_version: Option<String>,
    #[serde(default)]
    pub(crate) skip_linkers: Vec<LinkerKind>,
    /// Output format this benchmark produces. Drives host-platform
    /// filtering (Mach-O benches skip on Linux and vice versa) and
    /// linker-compatibility (ld64 only matches Mach-O benches).
    /// Defaults to ELF so existing TOMLs round-trip unchanged.
    #[serde(default)]
    pub(crate) platform: Platform,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Platform {
    Elf,
    Macho,
    /// `wasm32` (and `wasm64`) outputs. Linked by either `wild
    /// --target wasm32` or rust-lld's `wasm-ld` symlink. Unlike
    /// ELF/Mach-O, wasm has no notion of "native" host — the same
    /// linker invocation works from a Linux or macOS box — so wasm
    /// benches are NOT subject to the `Platform::host()` filter.
    Wasm,
}

impl Default for Platform {
    fn default() -> Self {
        Platform::Elf
    }
}

impl Platform {
    /// The platform that the *current host* produces natively. Used to
    /// skip benches that need a cross-platform linker we don't ship.
    /// Wasm benches deliberately live outside this filter (they run
    /// on either host); see `runs_on_host` below.
    pub(crate) fn host() -> Self {
        if cfg!(target_os = "macos") {
            Platform::Macho
        } else {
            Platform::Elf
        }
    }

    /// Whether this benchmark's output format can be produced on the
    /// current host without a cross-toolchain. Mach-O ⇒ macOS only;
    /// ELF ⇒ Linux only; Wasm ⇒ everywhere (wasm32 is target-only,
    /// no host-format dependency).
    pub(crate) fn runs_on_host(self, host: Platform) -> bool {
        match self {
            Platform::Wasm => true,
            other => other == host,
        }
    }
}

impl Config {
    pub(crate) fn load(config_path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read `{}`", config_path.display()))?;

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse `{}`", config_path.display()))
    }
}
