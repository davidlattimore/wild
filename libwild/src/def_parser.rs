use std::path::Path;

pub(crate) fn parse(path: &Path) -> Vec<String> {
    let content = std::fs::read_to_string(path).expect("TODO");

    // TODO: this is an lazily made abomination, do it properly
    content
        .trim()
        .strip_prefix('{')
        .unwrap()
        .strip_suffix("};")
        .unwrap()
        .split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_matches('"'))
        .map(String::from)
        .collect()
}
