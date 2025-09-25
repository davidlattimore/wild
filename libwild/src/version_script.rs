//! Support for version scripts. Version scripts are used for attaching versions to symbols when
//! producing a shared object and for controlling which symbols do and don't get exported. Version
//! scripts are technically part of the linker script syntax, via the VERSION command, but are
//! generally passed via the --version-script flag instead. They can also sometimes be quite large.
//! For this reason, we have a separate parser for them.

use crate::bail;
use crate::error;
use crate::error::Result;
use crate::hash::PassThroughHasher;
use crate::hash::PreHashed;
use crate::input_data::ScriptData;
use crate::linker_script::skip_comments_and_whitespace;
use crate::symbol::UnversionedSymbolName;
use glob::Pattern;
use hashbrown::HashMap;
use hashbrown::HashSet;
use symbolic_demangle::Demangle;
use symbolic_demangle::DemangleOptions;
use winnow::BStr;
use winnow::Parser;
use winnow::error::ContextError;
use winnow::error::FromExternalError;
use winnow::token::take_until;
use winnow::token::take_while;

#[derive(Debug, Default)]
pub(crate) struct MatchRules<'data> {
    pub(crate) general: BasicMatchRules<'data>,
    pub(crate) cxx: BasicMatchRules<'data>,
}

#[derive(Debug, Default)]
pub(crate) struct VersionBody<'data> {
    globals: MatchRules<'data>,
    locals: MatchRules<'data>,
}

#[derive(Debug, Default)]
pub(crate) struct Version<'data> {
    pub(crate) name: &'data [u8],
    pub(crate) parent_index: Option<u16>,
    pub(crate) version_body: VersionBody<'data>,
}

/// A version script. See https://sourceware.org/binutils/docs/ld/VERSION.html
#[derive(Default)]
pub(crate) struct VersionScript<'data> {
    versions: Vec<Version<'data>>,
    version_name_mapping: HashMap<&'data [u8], usize>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub(crate) enum SymbolMatcher<'data> {
    // Exact match.
    Exact(&'data [u8]),
    // Exact match with escape sequences that need unescaping.
    EscapedExact(&'data [u8]),
    // A glob pattern with a '*' token.
    StarGlob(Pattern),
    // A glob pattern without any '*' token.
    NonstarGlob(Pattern),
    /// Glob pattern equal to '*'
    MatchesAll,
}

#[derive(Debug, Default)]
pub(crate) struct BasicMatchRules<'data> {
    exact: HashSet<PreHashed<UnversionedSymbolName<'data>>, PassThroughHasher>,
    escaped_exact: HashSet<Vec<u8>>,
    star_globs: Vec<Pattern>,
    nonstar_globs: Vec<Pattern>,
    matches_all: bool,
}

impl<'data> BasicMatchRules<'data> {
    fn push(&mut self, pattern: SymbolMatcher<'data>) {
        match pattern {
            SymbolMatcher::MatchesAll => self.matches_all = true,
            SymbolMatcher::StarGlob(glob) => self.star_globs.push(glob),
            SymbolMatcher::NonstarGlob(glob) => self.nonstar_globs.push(glob),
            SymbolMatcher::Exact(exact) => {
                self.exact.insert(UnversionedSymbolName::prehashed(exact));
            }
            SymbolMatcher::EscapedExact(escaped) => {
                let unescaped = unescape_pattern(escaped);
                self.escaped_exact.insert(unescaped);
            }
        }
    }

    #[inline]
    pub(crate) fn matches_exact(
        &self,
        lookup: &mut SymbolLookupNameWrapper,
        mangled: bool,
    ) -> bool {
        // Check normal exact matches first
        if !self.exact.is_empty() {
            if mangled {
                let demangled_name = lookup.get_demangled_name();
                // The creation of UnversionedSymbolName should be relatively cheap as we construct
                // it at most twice.
                if self
                    .exact
                    .contains(&UnversionedSymbolName::prehashed(demangled_name.as_bytes()))
                {
                    return true;
                }
            } else if self.exact.contains(lookup.name) {
                return true;
            }
        }

        // Check escaped exact matches
        if !self.escaped_exact.is_empty() {
            let symbol_bytes = if mangled {
                let demangled_name = lookup.get_demangled_name();
                demangled_name.as_bytes()
            } else {
                lookup.name.bytes()
            };

            if self.escaped_exact.contains(symbol_bytes) {
                return true;
            }
        }

        false
    }

    #[inline]
    pub(crate) fn matches_glob(
        &self,
        lookup: &mut SymbolLookupNameWrapper,
        non_star: bool,
        mangled: bool,
    ) -> bool {
        let mut globs = if non_star {
            self.nonstar_globs.iter().peekable()
        } else {
            self.star_globs.iter().peekable()
        };
        // Early exit before we actually demangle the name.
        if globs.peek().is_none() {
            return false;
        }

        let name = if mangled {
            lookup.get_demangled_name()
        } else {
            lookup.get_name_string()
        };

        globs.any(|pattern| pattern.matches(name))
    }

    #[inline]
    pub(crate) fn matches_all(&self) -> bool {
        self.matches_all
    }
}

#[derive(Debug)]
enum VersionRuleSection {
    Global,
    Local,
}

#[derive(Debug)]
pub(crate) enum ParsedSymbolMatcher<'data> {
    Single(SymbolMatcher<'data>),
    Multiple(Vec<SymbolMatcher<'data>>),
    CxxMatchers(Vec<SymbolMatcher<'data>>),
}

impl<'data> MatchRules<'data> {
    pub(crate) fn push(&mut self, pattern: ParsedSymbolMatcher<'data>) {
        match pattern {
            ParsedSymbolMatcher::Single(single) => {
                self.general.push(single);
            }
            ParsedSymbolMatcher::Multiple(matchers) => {
                for matcher in matchers {
                    self.general.push(matcher);
                }
            }
            ParsedSymbolMatcher::CxxMatchers(matchers) => {
                for matcher in matchers {
                    self.cxx.push(matcher);
                }
            }
        }
    }
}

pub(crate) struct SymbolLookupNameWrapper<'data> {
    name: &'data PreHashed<UnversionedSymbolName<'data>>,
    name_string: Option<&'data str>,
    demangled_name: Option<String>,
}

impl<'data> SymbolLookupNameWrapper<'data> {
    pub(crate) fn from_name(name: &'data PreHashed<UnversionedSymbolName<'data>>) -> Self {
        Self {
            name,
            name_string: None,
            demangled_name: None,
        }
    }

    pub(crate) fn get_name_string(&mut self) -> &'data str {
        self.name_string.get_or_insert_with(|| {
            str::from_utf8(self.name.bytes()).unwrap_or_else(|_| {
                panic!(
                    "Valid utf-8 identifier expected: {}",
                    String::from_utf8_lossy(self.name.bytes())
                )
            })
        })
    }

    pub(crate) fn get_demangled_name(&mut self) -> &String {
        // Extract the name string before the closure to avoid double mutable borrow
        let name_string = self.get_name_string();
        self.demangled_name.get_or_insert_with(|| {
            symbolic_common::Name::new(
                name_string,
                symbolic_common::NameMangling::Mangled,
                symbolic_common::Language::Cpp,
            )
            .demangle(DemangleOptions::complete().return_type(false))
            // Consider the original name if the demangler returns None.
            .unwrap_or_else(|| name_string.to_string())
        })
    }
}

impl<'data> VersionScript<'data> {
    fn find_match(
        &self,
        name: &PreHashed<UnversionedSymbolName>,
    ) -> Option<(usize, VersionRuleSection)> {
        // Perform symbol lookup the same was as descried for the LLD (and partially Mold) linker:
        // https://maskray.me/blog/2020-11-26-all-about-symbol-versioning#version-script
        let mut lookup_name = SymbolLookupNameWrapper::from_name(name);

        // 1) The first version tag with an exact pattern wins.
        for (i, version) in self.versions.iter().enumerate() {
            let body = &version.version_body;

            if body.globals.general.matches_exact(&mut lookup_name, false) {
                return Some((i, VersionRuleSection::Global));
            } else if body.locals.general.matches_exact(&mut lookup_name, false) {
                return Some((i, VersionRuleSection::Local));
            // Intentionally try first non-mangled names as it's much cheaper test.
            } else if body.globals.cxx.matches_exact(&mut lookup_name, true) {
                return Some((i, VersionRuleSection::Global));
            } else if body.locals.cxx.matches_exact(&mut lookup_name, true) {
                return Some((i, VersionRuleSection::Local));
            }
        }

        // 2) Otherwise, the last version tag with a non-* wildcard pattern wins ('global' should be checked first).
        //    Otherwise, the last version tag with a * pattern wins.
        for &non_star in &[true, false] {
            for (i, version) in self.versions.iter().enumerate().rev() {
                let body = &version.version_body;
                if body
                    .globals
                    .general
                    .matches_glob(&mut lookup_name, non_star, false)
                    || body
                        .globals
                        .cxx
                        .matches_glob(&mut lookup_name, non_star, true)
                {
                    return Some((i, VersionRuleSection::Global));
                } else if body
                    .locals
                    .general
                    .matches_glob(&mut lookup_name, non_star, false)
                    || body
                        .locals
                        .cxx
                        .matches_glob(&mut lookup_name, non_star, true)
                {
                    return Some((i, VersionRuleSection::Local));
                }
            }
        }

        // 3) Otherwise, the last version tag with match all (*).
        for (i, version) in self.versions.iter().enumerate().rev() {
            let body = &version.version_body;
            if body.globals.general.matches_all || body.globals.cxx.matches_all {
                return Some((i, VersionRuleSection::Global));
            } else if body.locals.general.matches_all || body.locals.cxx.matches_all {
                return Some((i, VersionRuleSection::Local));
            }
        }

        None
    }
}

fn parse_version_script<'input>(input: &mut &'input BStr) -> winnow::Result<VersionScript<'input>> {
    // List of version names in the script, used to map parent version to version indexes
    let mut version_names: Vec<&[u8]> = Vec::new();

    skip_comments_and_whitespace(input)?;

    // Simple version script, only defines symbols visibility
    if input.starts_with(b"{") {
        let version_body = parse_version_section(input)?;

        ";".parse_next(input)?;

        skip_comments_and_whitespace(input)?;

        return Ok(VersionScript {
            versions: vec![Version {
                version_body,
                ..Default::default()
            }],
            version_name_mapping: HashMap::new(),
        });
    }

    let mut version_script = VersionScript::default();

    // Base version placeholder
    version_names.push(b"");
    version_script.versions.push(Version::default());

    while !input.is_empty() {
        let name = parse_token(input)?;

        skip_comments_and_whitespace(input)?;

        let version_body = parse_version_section(input)?;

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

        version_names.push(name);
        version_script.versions.push(Version {
            name,
            parent_index,
            version_body,
        });
        version_script
            .version_name_mapping
            .insert(name, version_script.versions.len() - 1);
    }

    Ok(version_script)
}

impl<'data> VersionScript<'data> {
    #[tracing::instrument(skip_all, name = "Parse version script")]
    pub(crate) fn parse(data: ScriptData<'data>) -> Result<VersionScript<'data>> {
        parse_version_script
            .parse(BStr::new(data.raw))
            .map_err(|err| error!("Failed to parse version script:\n{err}"))
    }

    pub(crate) fn is_local(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        self.find_match(name)
            .is_some_and(|(_, rule)| matches!(rule, VersionRuleSection::Local))
    }

    /// Number of versions in the Version Script, including the base version.
    pub(crate) fn version_count(&self) -> u16 {
        if self.versions.len() == 1 {
            // Ignore it if we have just the base version.
            0
        } else {
            self.versions.len() as u16
        }
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
        version_name: Option<&[u8]>,
    ) -> Result<Option<u16>> {
        let name_bytes = name.bytes();
        if let Some(version_name) = version_name {
            if let Some(&number) = self.version_name_mapping.get(version_name) {
                return Ok(Some(number as u16 + object::elf::VER_NDX_GLOBAL));
            }
            bail!(
                "Symbol {} has undefined version {}",
                String::from_utf8_lossy(name_bytes),
                String::from_utf8_lossy(version_name),
            );
        }

        Ok(self.find_match(name).and_then(|(number, _)| {
            if number == 0 {
                // Ignore the implicit version!
                None
            } else {
                Some(number as u16 + object::elf::VER_NDX_GLOBAL)
            }
        }))
    }
}

fn parse_version_section<'data>(input: &mut &'data BStr) -> winnow::Result<VersionBody<'data>> {
    let mut section = None;

    let mut out = VersionBody::default();

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
            let matcher = parse_matcher(input, false)?;

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

pub(crate) fn parse_matcher<'data>(
    input: &mut &'data BStr,
    without_semicolon: bool, // e.g. symbol to export passed via CLI arg
) -> winnow::Result<ParsedSymbolMatcher<'data>> {
    if input.starts_with(b"extern ") {
        let mut matchers = Vec::new();
        b"extern ".parse_next(input)?;
        let cxx = if input.starts_with(b"\"C++\"") {
            b"\"C++\"".parse_next(input)?;
            true
        } else if input.starts_with(b"\"C\"") {
            b"\"C\"".parse_next(input)?;
            false
        } else {
            let unsupported_extern: String = "{".parse_to().parse_next(input)?;
            return Err(ContextError::from_external_error(
                input,
                VersionScriptError::UnsupportedExtern(unsupported_extern),
            ));
        };
        skip_comments_and_whitespace(input)?;
        '{'.parse_next(input)?;

        loop {
            skip_comments_and_whitespace(input)?;

            if input.starts_with(b"};") {
                b"};".parse_next(input)?;
                skip_comments_and_whitespace(input)?;
                break;
            }

            // Symbols at the end of `extern` blocks may omit semicolons
            let expect_semicolon = {
                let remaining = &**input;
                if let Some(close_pos) = remaining.windows(2).position(|w| w == b"};") {
                    remaining[..close_pos].contains(&b';')
                } else {
                    without_semicolon
                }
            };

            let matcher = parse_matcher(input, !expect_semicolon)?;
            let ParsedSymbolMatcher::Single(matcher) = matcher else {
                let unexpected_extern = if matches!(matcher, ParsedSymbolMatcher::CxxMatchers(_)) {
                    "C++"
                } else {
                    "C"
                };
                return Err(ContextError::from_external_error(
                    input,
                    VersionScriptError::UnexpectedExtern(unexpected_extern.to_string()),
                ));
            };

            matchers.push(matcher);
        }

        if cxx {
            return Ok(ParsedSymbolMatcher::CxxMatchers(matchers));
        }
        return Ok(ParsedSymbolMatcher::Multiple(matchers));
    }

    let token = if without_semicolon {
        if input.contains(&b'}') {
            take_until(1.., b'}').parse_next(input)?
        } else {
            // TODO: Clippy bug
            #[allow(clippy::needless_borrow)]
            &input
        }
    } else {
        take_until(1.., b';').parse_next(input)?
    };

    skip_comments_and_whitespace(input)?;

    if input.starts_with(b";") {
        ";".parse_next(input)?;
    }

    let token = token.trim_ascii_end();

    Ok(ParsedSymbolMatcher::Single(
        if let Some(unquoted) = token
            .strip_prefix(b"\"")
            .and_then(|t| t.strip_suffix(b"\""))
        {
            SymbolMatcher::Exact(unquoted)
        } else if token == b"*" {
            SymbolMatcher::MatchesAll
        } else {
            let glob_type = analyze_glob_pattern(token);

            let create_pattern = |token: &[u8]| -> winnow::Result<Pattern> {
                Pattern::new(str::from_utf8(token).map_err(|_| {
                    ContextError::from_external_error(input, VersionScriptError::InvalidUtf8String)
                })?)
                .map_err(|_| {
                    ContextError::from_external_error(input, VersionScriptError::InvalidGlobPattern)
                })
            };

            match glob_type {
                GlobPatternType::Exact => SymbolMatcher::Exact(token),
                GlobPatternType::EscapedExact => SymbolMatcher::EscapedExact(token),
                GlobPatternType::Star => SymbolMatcher::StarGlob(create_pattern(token)?),
                GlobPatternType::NonStar => SymbolMatcher::NonstarGlob(create_pattern(token)?),
            }
        },
    ))
}

fn parse_token<'input>(input: &mut &'input BStr) -> winnow::Result<&'input [u8]> {
    take_while(1.., |b| !b" (){}\n\t".contains(&b)).parse_next(input)
}

enum GlobPatternType {
    Exact,
    EscapedExact,
    Star,
    NonStar,
}

fn analyze_glob_pattern(pattern: &[u8]) -> GlobPatternType {
    let mut pattern_type = GlobPatternType::Exact;
    let mut it = pattern.iter();

    while let Some(&c) = it.next() {
        match c {
            b'\\' => {
                // Found an escape sequence, mark as EscapedExact if no globs found yet
                if matches!(pattern_type, GlobPatternType::Exact) {
                    pattern_type = GlobPatternType::EscapedExact;
                }
                it.next();
            }
            b'*' => {
                return GlobPatternType::Star;
            }
            b'[' | b']' | b'?' => {
                pattern_type = GlobPatternType::NonStar;
            }
            _ => {}
        }
    }

    pattern_type
}

/// Unescapes a pattern by removing backslashes that escape special characters.
/// For exact patterns, we need to normalize escaped characters to their literal form.
fn unescape_pattern(pattern: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(pattern.len());
    let mut it = pattern.iter();

    while let Some(&c) = it.next() {
        if c == b'\\' {
            if let Some(&next_c) = it.next() {
                result.push(next_c);
            } else {
                // If backslash is at the end, include it as-is
                result.push(c);
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[derive(Debug)]
enum VersionScriptError {
    UnknownParentVersion,
    InvalidUtf8String,
    InvalidGlobPattern,
    UnexpectedExtern(String),
    UnsupportedExtern(String),
}

impl std::error::Error for VersionScriptError {}

impl std::fmt::Display for VersionScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionScriptError::InvalidGlobPattern => write!(f, "Invalid glob pattern"),
            VersionScriptError::InvalidUtf8String => write!(f, "Invalid utf-8 string"),
            VersionScriptError::UnknownParentVersion => write!(f, "Unknown parent version"),
            VersionScriptError::UnexpectedExtern(s) => {
                write!(f, "Unexpected extern \"{s}\" in parsing")
            }
            VersionScriptError::UnsupportedExtern(s) => write!(f, "Unsupported extern \"{s}\""),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use itertools::Itertools;
    use itertools::assert_equal;

    fn is_matching_global<'data>(script: &VersionScript<'data>, name: &str) -> bool {
        let Some(m) = script.find_match(&UnversionedSymbolName::prehashed(name.as_bytes())) else {
            return true;
        };
        matches!(m.1, VersionRuleSection::Global)
    }

    #[test]
    fn test_parse_simple_version_script() {
        let data = ScriptData {
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
        let version_body = &script.versions[0].version_body;
        assert_equal(
            version_body
                .globals
                .general
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo"],
        );
        assert_equal(
            version_body
                .globals
                .general
                .star_globs
                .iter()
                .map(|glob| glob.as_str()),
            ["bar*", "best_*_fn*", "*_wrapper"],
        );

        assert!(is_matching_global(&script, "main_wrapper"));
        assert!(is_matching_global(&script, "bar_bar_bar"));
        assert!(is_matching_global(&script, "best_foo_fn_barus"));
        assert!(!is_matching_global(&script, "best_fn"));
    }

    #[test]
    fn test_parse_version_script() {
        let data = ScriptData {
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

        let version = &script.versions[1];
        assert_eq!(version.name, b"VERS_1.1");
        assert_eq!(version.parent_index, None);
        assert_equal(
            version
                .version_body
                .globals
                .general
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo1"],
        );
        assert_equal(
            version
                .version_body
                .locals
                .general
                .star_globs
                .iter()
                .map(|glob| glob.as_str()),
            ["old*"],
        );

        let version = &script.versions[2];
        assert_eq!(version.name, b"VERS_1.2");
        assert_eq!(version.parent_index, Some(1));
        assert_equal(
            version
                .version_body
                .globals
                .general
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo2"],
        );
    }

    #[test]
    fn single_line_version_script() {
        let data = ScriptData {
            raw: br#"VERSION42 { global: *; };"#,
        };
        VersionScript::parse(data).unwrap();
    }

    #[test]
    fn extern_cxx_version_script() {
        let data = ScriptData {
            raw: br#"
                "VERSION42 {
                    local:
                        foo;
                        bar;
                        extern "C++" {
                            ns::*;
                            "f(int**,double)";
                            "std::vector<Loc<1>, std::allocator<Loc<1> > >::_M_realloc_append<Loc<1> const&>(Loc<1> const&)::_Guard_elts::_Guard_elts(Loc<1>*, std::allocator<Loc<1> >&)";
                            "WebKit::WebProcessMain(int, char**)";
                        };
                };"#,
        };
        let script = VersionScript::parse(data).unwrap();
        let version_body = &script.versions[1].version_body;

        assert_equal(
            version_body
                .locals
                .cxx
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap())
                .sorted(),
            [
                "WebKit::WebProcessMain(int, char**)",
                "f(int**,double)",
                "std::vector<Loc<1>, std::allocator<Loc<1> > >::_M_realloc_append<Loc<1> const&>(Loc<1> const&)::_Guard_elts::_Guard_elts(Loc<1>*, std::allocator<Loc<1> >&)",
            ],
        );
        assert_equal(
            version_body
                .locals
                .cxx
                .star_globs
                .iter()
                .map(|glob| glob.as_str()),
            ["ns::*"],
        );

        assert!(!is_matching_global(&script, "foo"));
        // Test "ns::" c++ namespace glob pattern.
        assert!(!is_matching_global(
            &script,
            "_ZN2ns8generateB5cxx11ENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEb"
        ));
        // Test exact matches after C++ demangling.
        assert!(!is_matching_global(
            &script,
            "_ZZNSt6vectorI3LocILi1EESaIS1_EE17_M_realloc_appendIJRKS1_EEEvDpOT_EN11_Guard_eltsC2EPS1_RS2_"
        ));
        assert!(!is_matching_global(
            &script,
            "_ZN6WebKit14WebProcessMainEiPPc"
        ));
        assert!(is_matching_global(
            &script,
            "_ZTVN10__cxxabiv120__si_class_type_infoE"
        ));
    }

    #[test]
    fn extern_c_version_script() {
        let data = ScriptData {
            raw: br#"
                "VERSION42 {
                    local:
                        foo;
                        bar;
                        extern "C" {
                            baz;
                        };
                };"#,
        };
        let script = VersionScript::parse(data).unwrap();
        let version_body = &script.versions[1].version_body;

        assert_equal(
            version_body
                .locals
                .general
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap())
                .sorted(),
            ["bar", "baz", "foo"],
        );
    }

    #[test]
    fn extern_without_semicolon_version_script() {
        let data = ScriptData {
            raw: br#"
                {
                    extern "C" {
                        foo
                    };
                };"#,
        };
        let script = VersionScript::parse(data).unwrap();
        let version_body = &script.versions[0].version_body;

        assert_equal(
            version_body
                .globals
                .general
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap()),
            ["foo"],
        );

        let data = ScriptData {
            raw: br#"
                {
                    extern "C++" {
                        bar;
                        baz
                    };
                };"#,
        };
        let script = VersionScript::parse(data).unwrap();
        let version_body = &script.versions[0].version_body;

        assert_equal(
            version_body
                .globals
                .cxx
                .exact
                .iter()
                .map(|s| std::str::from_utf8(s.bytes()).unwrap())
                .sorted(),
            ["bar", "baz"],
        );
    }

    #[test]
    fn invalid_version_scripts() {
        #[track_caller]
        fn assert_invalid(src: &str) {
            let data = ScriptData {
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

    #[test]
    fn test_version_order() {
        let data = ScriptData {
            raw: br#"
                VERS_1.1 {
                    foo;
                    foo?;
                    f*;
                    bar*;
                };

                VERS_1.2 {
                    foo*;
                    bar;
                } VERS_1.1;
            "#,
        };
        let script = VersionScript::parse(data).unwrap();
        let sym = UnversionedSymbolName::prehashed;

        // Exact match wins
        assert_eq!(script.find_match(&sym(b"foo")).unwrap().0, 1);
        assert_eq!(script.find_match(&sym(b"bar")).unwrap().0, 2);

        // Non-star match
        assert_eq!(script.find_match(&sym(b"foox")).unwrap().0, 1);

        // Star match
        assert_eq!(script.find_match(&sym(b"foo_bar")).unwrap().0, 2);
    }

    #[test]
    fn test_escape_sequences() {
        let data = ScriptData {
            raw: br#"
                {
                    global:
                        foo\*bar;
                        baz\?;
                        foo1\\foo2;
                        foo3?foo4*;
                        b*;
                        f?;
                };
            "#,
        };
        let script = VersionScript::parse(data).unwrap();
        let version_body = &script.versions[0].version_body;

        let escaped_patterns: HashSet<&[u8]> = version_body
            .globals
            .general
            .escaped_exact
            .iter()
            .map(|v| v.as_slice())
            .collect();

        assert!(escaped_patterns.contains(&b"foo*bar"[..]));
        assert!(escaped_patterns.contains(&b"baz?"[..]));
        assert!(escaped_patterns.contains(&b"foo1\\foo2"[..]));

        let star_patterns: Vec<&str> = version_body
            .globals
            .general
            .star_globs
            .iter()
            .map(|glob| glob.as_str())
            .collect();

        assert!(star_patterns.contains(&"b*"));
        assert!(star_patterns.contains(&"foo3?foo4*"));

        let nonstar_patterns: Vec<&str> = version_body
            .globals
            .general
            .nonstar_globs
            .iter()
            .map(|glob| glob.as_str())
            .collect();

        assert!(nonstar_patterns.contains(&"f?"));
    }
}
