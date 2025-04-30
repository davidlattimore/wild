//! Support for version scripts. Version scripts are used for attaching versions to symbols when
//! producing a shared object and for controlling which symbols do and don't get exported. Version
//! scripts are technically part of the linker script syntax, via the VERSION command, but are
//! generally passed via the --version-script flag instead. They can also sometimes be quite large.
//! For this reason, we have a separate parser for them.

use crate::error::Result;
use crate::hash::PassThroughHasher;
use crate::hash::PreHashed;
use crate::input_data::VersionScriptData;
use crate::symbol::UnversionedSymbolName;
use anyhow::Context as _;
use anyhow::anyhow;
use anyhow::bail;
use std::collections::HashSet;

/// A version script. See https://sourceware.org/binutils/docs/ld/VERSION.html
#[derive(Default)]
pub(crate) struct VersionScript<'data> {
    /// For symbol visibility we only need to know whether the symbol is global or local.
    globals: MatchRules<'data>,
    locals: MatchRules<'data>,
    versions: Vec<Version<'data>>,
}

pub(crate) struct Version<'data> {
    pub(crate) name: &'data [u8],
    pub(crate) parent_index: Option<u16>,
    symbols: MatchRules<'data>,
}

#[derive(Default)]
struct MatchRules<'data> {
    matches_all: bool,
    exact: HashSet<PreHashed<UnversionedSymbolName<'data>>, PassThroughHasher>,
    prefixes: Vec<&'data [u8]>,
}

impl<'data> MatchRules<'data> {
    fn push(&mut self, pattern: SymbolMatcher<'data>) {
        match pattern {
            SymbolMatcher::All => self.matches_all = true,
            SymbolMatcher::Prefix(prefix) => self.prefixes.push(prefix),
            SymbolMatcher::Exact(exact) => {
                self.exact.insert(UnversionedSymbolName::prehashed(exact));
            }
        }
    }

    fn matches(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.matches_all
            || self.exact.contains(name)
            || self
                .prefixes
                .iter()
                .any(|prefix| name.bytes().starts_with(prefix))
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SymbolMatcher<'data> {
    All,
    Prefix(&'data [u8]),
    Exact(&'data [u8]),
}

impl<'data> VersionScript<'data> {
    #[tracing::instrument(skip_all, name = "Parse version script")]
    pub(crate) fn parse(data: VersionScriptData<'data>) -> Result<VersionScript<'data>> {
        let mut tokens = Tokeniser::new(data.raw);
        let mut version_script = Self::default();

        // List of version names in the script, used to map parent version to version indexes
        let mut version_names: Vec<&[u8]> = Vec::new();

        tokens.text = trim(tokens.text);

        let mut token = tokens.next().ok_or_else(|| anyhow!("No tokens found"))?;
        // Simple version script, only defines symbols visibility
        if token.starts_with(b"{") {
            parse_version_section(
                &mut tokens,
                &mut version_script.locals,
                &mut version_script.globals,
                None,
            )?;
            return Ok(version_script);
        }

        // Base version placeholder
        version_names.push(b"");
        version_script.versions.push(Version {
            name: b"",
            symbols: MatchRules::default(),
            parent_index: None,
        });

        loop {
            tokens.expect(b"{")?;
            version_names.push(token);

            let mut version_symbols = MatchRules::default();
            let parent = parse_version_section(
                &mut tokens,
                &mut version_script.locals,
                &mut version_script.globals,
                Some(&mut version_symbols),
            )?;
            let parent_index = if let Some(parent) = parent {
                // TODO: For longer version scripts IndexSet makes sense, but is it even realistic use case?
                Some(
                    version_names
                        .iter()
                        .position(|v| v == &parent)
                        .with_context(|| {
                            format!("Could not find version {}", String::from_utf8_lossy(parent))
                        })? as u16,
                )
            } else {
                None
            };

            version_script.versions.push(Version {
                name: token,
                parent_index,
                symbols: version_symbols,
            });

            // Next version for the symbols
            if let Some(next_token) = tokens.next() {
                token = next_token;
            } else {
                break;
            };
        }

        Ok(version_script)
    }

    pub(crate) fn is_local(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        if self.globals.matches(name) {
            return false;
        }
        self.locals.matches(name)
    }

    /// Number of versions in the Version Script, including the base version.
    pub(crate) fn version_count(&self) -> u16 {
        self.versions.len() as u16
    }

    pub(crate) fn parent_count(&self) -> u16 {
        self.versions
            .iter()
            .filter(|v| v.parent_index.is_some())
            .count() as u16
    }

    pub(crate) fn version_iter(&self) -> impl Iterator<Item = &Version> {
        self.versions.iter()
    }

    pub(crate) fn version_for_symbol(
        &self,
        name: &PreHashed<UnversionedSymbolName>,
    ) -> Option<u16> {
        self.versions.iter().enumerate().find_map(|(number, ver)| {
            ver.is_present(name)
                .then(|| number as u16 + object::elf::VER_NDX_GLOBAL)
        })
    }
}

fn trim(text: &[u8]) -> &[u8] {
    trim_start(trim_end(text))
}

const WHITESPACE: &[u8] = b" \n\r\t";

fn trim_start(text: &[u8]) -> &[u8] {
    if let Some(pos) = text.iter().position(|b| !WHITESPACE.contains(b)) {
        return &text[pos..];
    }
    text
}

fn trim_end(text: &[u8]) -> &[u8] {
    if let Some(pos) = text.iter().rev().position(|b| !WHITESPACE.contains(b)) {
        return &text[..text.len() - pos];
    }
    text
}

enum VersionRuleSection {
    Global,
    Local,
}

/// Parses contents after opening brace up to closing brace, adding symbols to the respective rules.
/// Returns contents after closing brace if any.
fn parse_version_section<'data>(
    tokens: &mut Tokeniser<'data>,
    locals: &mut MatchRules<'data>,
    globals: &mut MatchRules<'data>,
    mut versioned_symbols: Option<&mut MatchRules<'data>>,
) -> Result<Option<&'data [u8]>> {
    let mut section = None;

    // We read line-by-line rather than token-by-token because it's much faster. This is
    // important when for example rustc emits a version script that's more than 300k lines.
    while let Some(line) = tokens.next_line() {
        let mut line = trim(line);
        if let Some(parent_string) = line.strip_prefix(b"}") {
            if parent_string.starts_with(b";") {
                return Ok(None);
            }
            return Ok(trim(parent_string).strip_suffix(b";"));
        }
        // Note, we don't currently support comments that have content after them on the same
        // line. Doing so would require us to search every line for embedded comments, which
        // would hurt performance.
        if line.ends_with(b"*/") {
            if let Some(start_index) = line.windows(2).position(|w| w == b"/*") {
                line = trim(&line[..start_index]);
            }
        }

        if line.starts_with(b"/*") {
            while let Some(line) = tokens.next_line() {
                if line.ends_with(b"*/") {
                    break;
                }
            }
        } else if line == b"global:" {
            section = Some(VersionRuleSection::Global);
        } else if line == b"local:" {
            section = Some(VersionRuleSection::Local);
        } else if let Some(pattern) = line.strip_suffix(b";") {
            match section {
                Some(VersionRuleSection::Global) | None => {
                    globals.push(SymbolMatcher::from_pattern(pattern)?);
                }
                Some(VersionRuleSection::Local) => {
                    locals.push(SymbolMatcher::from_pattern(pattern)?);
                }
            }
            if let Some(versioned_symbols) = versioned_symbols.as_deref_mut() {
                versioned_symbols.push(SymbolMatcher::from_pattern(pattern)?);
            }
        } else if !line.is_empty() {
            bail!(
                "Unsupported version script line `{}`",
                String::from_utf8_lossy(line)
            );
        }
    }
    bail!("Missing close '}}' in version script");
}

impl Version<'_> {
    fn is_present(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.symbols.matches(name)
    }
}

impl<'data> SymbolMatcher<'data> {
    fn from_pattern(token: &'data [u8]) -> Result<SymbolMatcher<'data>> {
        if token == b"*" {
            return Ok(SymbolMatcher::All);
        }
        if let Some(prefix) = token.strip_suffix(b"*") {
            if prefix.contains(&b'*') {
                bail!(
                    "Unsupported symbol pattern '{}'",
                    String::from_utf8_lossy(token)
                );
            }
            return Ok(SymbolMatcher::Prefix(prefix));
        }
        if token.contains(&b'*') {
            bail!(
                "Unsupported symbol pattern '{}'",
                String::from_utf8_lossy(token)
            );
        }
        Ok(SymbolMatcher::Exact(token))
    }
}

struct Tokeniser<'a> {
    text: &'a [u8],
}

impl<'a> Tokeniser<'a> {
    fn next(&mut self) -> Option<&'a [u8]> {
        loop {
            self.text = trim_start(self.text);
            if try_take(&mut self.text, b"/*") {
                if take_up_to(&mut self.text, b"*/").is_err() {
                    self.text = b"";
                }
                continue;
            }
            if self.text.starts_with(b"#") {
                if take_up_to(&mut self.text, b"\n").is_err() {
                    self.text = b"";
                }
                continue;
            }
            if self.text.is_empty() {
                return None;
            }
            let bytes = self.text;
            let mut len = 0;
            for byte in bytes {
                if b" \n\t(){};".contains(byte) {
                    break;
                }
                len += 1;
            }
            if len == 0 {
                len = 1;
            }
            let token = &self.text[..len];
            self.text = &self.text[len..];
            return Some(token);
        }
    }

    fn next_line(&mut self) -> Option<&'a [u8]> {
        while let Some(rest) = self.text.strip_prefix(b"\n") {
            self.text = rest;
        }
        if self.text.is_empty() {
            return None;
        }
        let bytes = self.text;
        let end_pos = memchr::memchr(b'\n', bytes).unwrap_or(bytes.len());
        let (line, rest) = self.text.split_at(end_pos);
        self.text = rest;
        Some(line)
    }

    fn new(text: &'a [u8]) -> Self {
        Tokeniser { text }
    }

    fn expect(&mut self, expected: &[u8]) -> Result {
        let token = self.next().ok_or_else(|| {
            anyhow!(
                "Expected token '{}', got end of input",
                String::from_utf8_lossy(expected)
            )
        })?;
        if token != expected {
            bail!(
                "Expected token '{}', got '{}'",
                String::from_utf8_lossy(expected),
                String::from_utf8_lossy(token)
            );
        }
        Ok(())
    }
}

fn try_take(input: &mut &[u8], pattern: &[u8]) -> bool {
    if let Some(rest) = input.strip_prefix(pattern) {
        *input = rest;
        true
    } else {
        false
    }
}

fn take_up_to<'a>(input: &mut &'a [u8], pattern: &[u8]) -> Result<&'a [u8]> {
    let end = input
        .windows(pattern.len())
        .position(|w| w == pattern)
        .ok_or_else(|| anyhow!("Missing expected '{}'", String::from_utf8_lossy(pattern)))?;
    let content = &input[..end];
    *input = &input[end + pattern.len()..];
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use itertools::assert_equal;

    #[test]
    fn test_tokenisation() {
        fn tokenise(text: &str) -> Vec<&str> {
            let mut t = Tokeniser::new(text.as_bytes());
            let mut out = Vec::new();
            while let Some(token) = t.next() {
                assert!(!token.is_empty());
                out.push(std::str::from_utf8(token).unwrap());
            }
            out
        }

        assert_eq!(tokenise("/**/ /* a */ GROUP ()"), vec!["GROUP", "(", ")"]);
        assert_eq!(
            tokenise("GROUP ( AS_NEEDED ( /a/b/c ))"),
            vec!["GROUP", "(", "AS_NEEDED", "(", "/a/b/c", ")", ")"]
        );
        assert_eq!(tokenise(""), Vec::<&str>::new());
    }

    #[test]
    fn test_parse_simple_version_script() {
        let data = VersionScriptData {
            raw: br#"
                    # Comment starting with a hash
                    {global:
                        /* Single-line comment */
                        foo; /* Trailing comment */
                        bar*;
                    local:
                        /* Multi-line
                           comment */
                        *;
                    }"#,
        };
        let script = VersionScript::parse(data).unwrap();
        assert_equal(
            script
                .globals
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo"],
        );
        assert_equal(
            script
                .globals
                .prefixes
                .iter()
                .map(|s| std::str::from_utf8(s).unwrap()),
            ["bar"],
        );
        assert!(script.locals.matches_all);
    }

    #[test]
    fn test_parse_version_script() {
        let data = VersionScriptData {
            raw: br#"
                VERS_1.1 {
                    global:
                        foo1;
                    local:
                        old*;
                };

                VERS_1.2 {
                    foo2;
                } VERS_1.1;
            "#,
        };
        let script = VersionScript::parse(data).unwrap();
        assert_eq!(script.versions.len(), 3);
        assert_equal(
            script
                .globals
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap())
                .sorted(),
            ["foo1", "foo2"],
        );
        assert_equal(
            script
                .locals
                .prefixes
                .iter()
                .map(|s| std::str::from_utf8(s).unwrap()),
            ["old"],
        );

        let version = &script.versions[1];
        assert_eq!(version.name, b"VERS_1.1");
        assert_eq!(version.parent_index, None);
        assert_equal(
            version
                .symbols
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo1"],
        );
        assert_equal(
            version
                .symbols
                .prefixes
                .iter()
                .map(|s| std::str::from_utf8(s).unwrap()),
            ["old"],
        );

        let version = &script.versions[2];
        assert_eq!(version.name, b"VERS_1.2");
        assert_eq!(version.parent_index, Some(1));
        assert_equal(
            version
                .symbols
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo2"],
        );
    }
}
