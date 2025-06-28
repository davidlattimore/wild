//! Support for version scripts. Version scripts are used for attaching versions to symbols when
//! producing a shared object and for controlling which symbols do and don't get exported. Version
//! scripts are technically part of the linker script syntax, via the VERSION command, but are
//! generally passed via the --version-script flag instead. They can also sometimes be quite large.
//! For this reason, we have a separate parser for them.

use crate::error;
use crate::error::Result;
use crate::hash::PassThroughHasher;
use crate::hash::PreHashed;
use crate::input_data::VersionScriptData;
use crate::linker_script::skip_comments_and_whitespace;
use crate::symbol::UnversionedSymbolName;
use glob::Pattern;
use std::collections::HashSet;
use winnow::BStr;
use winnow::Parser;
use winnow::error::ContextError;
use winnow::error::FromExternalError;
use winnow::token::take_until;
use winnow::token::take_while;

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
    globs: Vec<Pattern>,
}

impl<'data> MatchRules<'data> {
    fn push(&mut self, pattern: SymbolMatcher<'data>) {
        match pattern {
            SymbolMatcher::All => self.matches_all = true,
            SymbolMatcher::Glob(glob) => self.globs.push(glob),
            SymbolMatcher::Exact(exact) => {
                self.exact.insert(UnversionedSymbolName::prehashed(exact));
            }
        }
    }

    fn matches(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.matches_all
            || self.exact.contains(name)
            || self.globs.iter().any(|glob| {
                glob.matches(str::from_utf8(name.bytes()).unwrap_or_else(|_| {
                    panic!(
                        "Valid utf-8 identifier expected: {}",
                        String::from_utf8_lossy(name.bytes())
                    )
                }))
            })
    }

    fn merge(&mut self, other: &MatchRules<'data>) {
        if other.matches_all {
            self.matches_all = true;
        }

        if self.matches_all {
            self.exact.clear();
            self.globs.clear();
            return;
        }

        self.exact.extend(&other.exact);
        self.globs.extend(other.globs.iter().cloned());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum SymbolMatcher<'data> {
    All,
    Glob(Pattern),
    Exact(&'data [u8]),
}

fn parse_version_script<'input>(input: &mut &'input BStr) -> winnow::Result<VersionScript<'input>> {
    // List of version names in the script, used to map parent version to version indexes
    let mut version_names: Vec<&[u8]> = Vec::new();

    skip_comments_and_whitespace(input)?;

    // Simple version script, only defines symbols visibility
    if input.starts_with(b"{") {
        let script = parse_version_section(input)?;

        ";".parse_next(input)?;

        skip_comments_and_whitespace(input)?;

        return Ok(script);
    }

    let mut version_script = VersionScript::default();

    // Base version placeholder
    version_names.push(b"");
    version_script.versions.push(Version {
        name: b"",
        symbols: MatchRules::default(),
        parent_index: None,
    });

    while !input.is_empty() {
        let name = parse_token(input)?;

        skip_comments_and_whitespace(input)?;

        let version = parse_version_section(input)?;

        let parent_name = take_until(0.., b';').parse_next(input)?;

        let parent_index = if parent_name.is_empty() {
            None
        } else {
            // We don't expect lots of versions, so a linear scan seems reasonable.
            Some(
                version_names
                    .iter()
                    .position(|v| v == &parent_name)
                    .ok_or_else(|| {
                        ContextError::from_external_error(
                            input,
                            VersionScriptError::UnknownParentVersion,
                        )
                    })? as u16,
            )
        };

        ";".parse_next(input)?;

        skip_comments_and_whitespace(input)?;

        version_script.globals.merge(&version.globals);
        version_script.locals.merge(&version.locals);

        let mut version_symbols = MatchRules::default();
        version_symbols.merge(&version.globals);
        version_symbols.merge(&version.locals);

        version_names.push(name);

        version_script.versions.push(Version {
            name,
            parent_index,
            symbols: version_symbols,
        });
    }

    Ok(version_script)
}

impl<'data> VersionScript<'data> {
    #[tracing::instrument(skip_all, name = "Parse version script")]
    pub(crate) fn parse(data: VersionScriptData<'data>) -> Result<VersionScript<'data>> {
        parse_version_script
            .parse(BStr::new(data.raw))
            .map_err(|err| error!("Failed to parse version script:\n{err}"))
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

    pub(crate) fn version_iter(&self) -> impl Iterator<Item = &Version<'data>> {
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

enum VersionRuleSection {
    Global,
    Local,
}

fn parse_version_section<'data>(input: &mut &'data BStr) -> winnow::Result<VersionScript<'data>> {
    let mut section = None;

    let mut out = VersionScript::default();

    '{'.parse_next(input)?;

    loop {
        skip_comments_and_whitespace(input)?;

        if input.starts_with(b"}") {
            '}'.parse_next(input)?;
            skip_comments_and_whitespace(input)?;
            break;
        }

        if input.starts_with(b"global:") {
            "global:".parse_next(input)?;
            section = Some(VersionRuleSection::Global);
        } else if input.starts_with(b"local:") {
            "local:".parse_next(input)?;
            section = Some(VersionRuleSection::Local);
        } else {
            let matcher = parse_matcher(input)?;

            match section {
                Some(VersionRuleSection::Global) | None => {
                    out.globals.push(matcher);
                }
                Some(VersionRuleSection::Local) => {
                    out.locals.push(matcher);
                }
            }
        }
    }

    Ok(out)
}

impl Version<'_> {
    fn is_present(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.symbols.matches(name)
    }
}

fn parse_matcher<'data>(input: &mut &'data BStr) -> winnow::Result<SymbolMatcher<'data>> {
    let token = take_until(1.., b';').parse_next(input)?;

    skip_comments_and_whitespace(input)?;

    if input.starts_with(b";") {
        ";".parse_next(input)?;
    }

    let token = token.trim_ascii_end();
    Ok(if token == b"*" {
        SymbolMatcher::All
    } else if token.contains(&b'*') {
        SymbolMatcher::Glob(
            Pattern::new(str::from_utf8(token).map_err(|_| {
                ContextError::from_external_error(input, VersionScriptError::InvalidUtf8String)
            })?)
            .map_err(|_: glob::PatternError| {
                ContextError::from_external_error(input, VersionScriptError::InvalidGlobPattern)
            })?,
        )
    } else {
        SymbolMatcher::Exact(token)
    })
}

fn parse_token<'input>(input: &mut &'input BStr) -> winnow::Result<&'input [u8]> {
    take_while(1.., |b| !b" (){}\n\t".contains(&b)).parse_next(input)
}

#[derive(Debug)]
enum VersionScriptError {
    UnknownParentVersion,
    InvalidUtf8String,
    InvalidGlobPattern,
}

impl std::error::Error for VersionScriptError {}

impl std::fmt::Display for VersionScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionScriptError::InvalidGlobPattern => write!(f, "Invalid glob pattern"),
            VersionScriptError::InvalidUtf8String => write!(f, "Invalid utf-8 string"),
            VersionScriptError::UnknownParentVersion => write!(f, "Unknown parent version"),
        }
    }
}

impl std::fmt::Debug for Version<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Version")
            .field("name", &String::from_utf8_lossy(self.name))
            .field("parent_index", &self.parent_index)
            .field("symbols", &self.symbols)
            .finish()
    }
}

impl std::fmt::Debug for MatchRules<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MatchRules")
            .field("matches_all", &self.matches_all)
            .field("exact", &self.exact)
            .field("prefixes", &self.globs)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use itertools::assert_equal;

    #[test]
    fn test_parse_simple_version_script() {
        let data = VersionScriptData {
            raw: br#"
                    # Comment starting with a hash
                    {global:
                        /* Single-line comment */
                        foo; /* Trailing comment */
                        bar*;
                        best_*_fn*;
                        *_wrapper  ;
                    local:
                        /* Multi-line
                           comment */
                        *;
                    };"#,
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
            script.globals.globs.iter().map(|glob| glob.as_str()),
            ["bar*", "best_*_fn*", "*_wrapper"],
        );
        assert!(script.locals.matches_all);

        let globals = script.globals;
        assert!(globals.matches(&UnversionedSymbolName::prehashed(b"main_wrapper")));
        assert!(globals.matches(&UnversionedSymbolName::prehashed(b"bar_bar_bar")));
        assert!(globals.matches(&UnversionedSymbolName::prehashed(b"best_foo_fn_barus")));
        assert!(!globals.matches(&UnversionedSymbolName::prehashed(b"best_fn")));
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
            script.locals.globs.iter().map(|glob| glob.as_str()),
            ["old*"],
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
            version.symbols.globs.iter().map(|glob| glob.as_str()),
            ["old*"],
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

    #[test]
    fn single_line_version_script() {
        let data = VersionScriptData {
            raw: br#"VERSION42 { global: *; };"#,
        };
        let script = VersionScript::parse(data).unwrap();
        assert!(script.globals.matches_all);
    }

    #[test]
    fn invalid_version_scripts() {
        #[track_caller]
        fn assert_invalid(src: &str) {
            let data = VersionScriptData {
                raw: src.as_bytes(),
            };
            assert!(VersionScript::parse(data).is_err());
        }

        // Missing ';'
        assert_invalid("{}");
        assert_invalid("{*};");
        assert_invalid("{foo};");

        // Missing '}'
        assert_invalid("{foo;");
        assert_invalid("VER1 {foo;}; VER2 {bar;} VER1");

        // Missing parent version
        assert_invalid("VER2 {bar;} VER1;");
    }
}
