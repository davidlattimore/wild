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
use symbolic_demangle::Demangle;
use symbolic_demangle::DemangleOptions;
use winnow::BStr;
use winnow::Parser;
use winnow::error::ContextError;
use winnow::error::FromExternalError;
use winnow::token::take_until;
use winnow::token::take_while;

#[derive(Debug, Default)]
struct MatchRules<'data> {
    general: BasicMatchRules<'data>,
    cxx: BasicMatchRules<'data>,
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
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum SymbolMatcher<'data> {
    // Exact match.
    Exact(&'data [u8]),
    // A glob pattern with a '*' token.
    StarGlob(Pattern),
    // A glob pattern without any '*' token.
    NonstarGlob(Pattern),
    /// Glob pattern equal to '*'
    MatchesAll,
}

#[derive(Debug, Default)]
struct BasicMatchRules<'data> {
    exact: HashSet<PreHashed<UnversionedSymbolName<'data>>, PassThroughHasher>,
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
        }
    }

    #[inline]
    fn matches_exact(&self, lookup: &mut SymbolLookupNameWrapper, mangled: bool) -> bool {
        // Early exit before we actually demangle the name.
        if self.exact.is_empty() {
            return false;
        }

        if mangled {
            let demangled_name = lookup.get_demangled_name();
            // The creation of UnversionedSymbolName should be relatively cheap as we construct
            // it at most twice.
            self.exact
                .contains(&UnversionedSymbolName::prehashed(demangled_name.as_bytes()))
        } else {
            self.exact.contains(lookup.name)
        }
    }

    #[inline]
    fn matches_glob(
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
}

enum VersionRuleSection {
    Global,
    Local,
}

#[derive(Debug)]
enum ParsedSymbolMatcher<'data> {
    Single(SymbolMatcher<'data>),
    CxxMatchers(Vec<SymbolMatcher<'data>>),
}

impl<'data> MatchRules<'data> {
    fn push(&mut self, pattern: ParsedSymbolMatcher<'data>) {
        match pattern {
            ParsedSymbolMatcher::Single(single) => {
                self.general.push(single);
            }
            ParsedSymbolMatcher::CxxMatchers(matchers) => {
                for matcher in matchers {
                    self.cxx.push(matcher);
                }
            }
        }
    }
}

struct SymbolLookupNameWrapper<'data> {
    name: &'data PreHashed<UnversionedSymbolName<'data>>,
    name_string: Option<&'data str>,
    demangled_name: Option<String>,
}

impl<'data> SymbolLookupNameWrapper<'data> {
    fn from_name(name: &'data PreHashed<UnversionedSymbolName<'data>>) -> Self {
        Self {
            name,
            name_string: None,
            demangled_name: None,
        }
    }

    fn get_name_string(&mut self) -> &'data str {
        self.name_string.get_or_insert_with(|| {
            str::from_utf8(self.name.bytes()).unwrap_or_else(|_| {
                panic!(
                    "Valid utf-8 identifier expected: {}",
                    String::from_utf8_lossy(self.name.bytes())
                )
            })
        })
    }

    fn get_demangled_name(&mut self) -> &String {
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
    ) -> Option<u16> {
        self.find_match(name).and_then(|(number, _)| {
            if number == 0 {
                // Ignore the implicit version!
                None
            } else {
                Some(number as u16 + object::elf::VER_NDX_GLOBAL)
            }
        })
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

fn parse_matcher<'data>(input: &mut &'data BStr) -> winnow::Result<ParsedSymbolMatcher<'data>> {
    if input.starts_with(b"extern \"C++\"") {
        let mut matchers = Vec::new();
        b"extern \"C++\"".parse_next(input)?;
        skip_comments_and_whitespace(input)?;
        '{'.parse_next(input)?;

        loop {
            skip_comments_and_whitespace(input)?;

            if input.starts_with(b"};") {
                b"};".parse_next(input)?;
                skip_comments_and_whitespace(input)?;
                break;
            }

            let matcher = parse_matcher(input)?;
            let ParsedSymbolMatcher::Single(matcher) = matcher else {
                return Err(ContextError::from_external_error(
                    input,
                    VersionScriptError::UnexpectedExternCxx,
                ));
            };

            matchers.push(matcher);
        }

        return Ok(ParsedSymbolMatcher::CxxMatchers(matchers));
    }

    let token = take_until(1.., b';').parse_next(input)?;

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
        } else if token.contains(&b'\\') {
            return Err(ContextError::from_external_error(
                input,
                VersionScriptError::GlobWithQuote,
            ));
        } else if token == b"*" {
            SymbolMatcher::MatchesAll
        } else if b"[]?*".iter().any(|c| token.contains(c)) {
            let pattern = Pattern::new(str::from_utf8(token).map_err(|_| {
                ContextError::from_external_error(input, VersionScriptError::InvalidUtf8String)
            })?)
            .map_err(|_: glob::PatternError| {
                ContextError::from_external_error(input, VersionScriptError::InvalidGlobPattern)
            })?;

            if token.contains(&b'*') {
                SymbolMatcher::StarGlob(pattern)
            } else {
                SymbolMatcher::NonstarGlob(pattern)
            }
        } else {
            SymbolMatcher::Exact(token)
        },
    ))
}

fn parse_token<'input>(input: &mut &'input BStr) -> winnow::Result<&'input [u8]> {
    take_while(1.., |b| !b" (){}\n\t".contains(&b)).parse_next(input)
}

#[derive(Debug)]
enum VersionScriptError {
    UnknownParentVersion,
    InvalidUtf8String,
    InvalidGlobPattern,
    GlobWithQuote,
    UnexpectedExternCxx,
}

impl std::error::Error for VersionScriptError {}

impl std::fmt::Display for VersionScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionScriptError::InvalidGlobPattern => write!(f, "Invalid glob pattern"),
            VersionScriptError::GlobWithQuote => write!(f, "Globs with quote are unsupported"),
            VersionScriptError::InvalidUtf8String => write!(f, "Invalid utf-8 string"),
            VersionScriptError::UnknownParentVersion => write!(f, "Unknown parent version"),
            VersionScriptError::UnexpectedExternCxx => {
                write!(f, "Unexpected extern \"C++\" in parsing")
            }
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
        let data = VersionScriptData {
            raw: br#"VERSION42 { global: *; };"#,
        };
        VersionScript::parse(data).unwrap();
    }

    #[test]
    fn extern_cxx_version_script() {
        let data = VersionScriptData {
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

    #[test]
    fn test_version_order() {
        let data = VersionScriptData {
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
}
