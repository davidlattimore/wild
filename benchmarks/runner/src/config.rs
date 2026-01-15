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
}

impl Config {
    pub(crate) fn load(config_path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read `{}`", config_path.display()))?;

        toml::from_str(&contents)
            .with_context(|| format!("Failed to parse `{}`", config_path.display()))
    }
}
