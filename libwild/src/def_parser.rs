use crate::error;
use crate::error::Result;
use crate::hash::PreHashed;
use crate::input_data::VersionScriptData;
use crate::linker_script::skip_comments_and_whitespace;
use crate::symbol::UnversionedSymbolName;
use crate::version_script::BasicMatchRules;
use crate::version_script::ParsedSymbolMatcher;
use crate::version_script::SymbolLookupNameWrapper;
use crate::version_script::SymbolMatcher;
use glob::Pattern;
use winnow::BStr;
use winnow::Parser;
use winnow::error::ContextError;
use winnow::error::FromExternalError as _;
use winnow::token::take_until;

#[derive(Default)]
pub(crate) struct ExportSymbolList<'data> {
    enabled: bool,
    general: BasicMatchRules<'data>,
    cxx: BasicMatchRules<'data>,
}

impl<'data> ExportSymbolList<'data> {
    pub(crate) fn parse(data: VersionScriptData<'data>) -> Result<Self> {
        parse_wip
            .parse(BStr::new(data.raw))
            .map_err(|err| error!("Failed to parse version script:\n{err}"))
    }

    pub(crate) fn contains(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        // Perform symbol lookup the same was as descried for the LLD (and partially Mold) linker:
        // https://maskray.me/blog/2020-11-26-all-about-symbol-versioning#version-script
        let mut lookup_name = SymbolLookupNameWrapper::from_name(name);

        // 1) The first version tag with an exact pattern wins.
        if self.general.matches_exact(&mut lookup_name, false) {
            return true;
        // Intentionally try first non-mangled names as it's much cheaper test.
        } else if self.cxx.matches_exact(&mut lookup_name, true) {
            return true;
        }

        // 2) Otherwise, the last version tag with a non-* wildcard pattern wins ('global' should be checked first).
        //    Otherwise, the last version tag with a * pattern wins.
        for &non_star in &[true, false] {
            if self.general.matches_glob(&mut lookup_name, non_star, false)
                || self.cxx.matches_glob(&mut lookup_name, non_star, true)
            {
                return true;
            }
        }

        // 3) Otherwise, the last version tag with match all (*).
        if self.general.matches_all || self.cxx.matches_all {
            return true;
        }

        false
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn add_symbol(&mut self, symbol: &'data str) -> Result<()> {
        let matcher = parse_matcher(&mut BStr::new(symbol), true)?;
        match matcher {
            ParsedSymbolMatcher::Single(single) => {
                self.general.push(single);
            }
            ParsedSymbolMatcher::CxxMatchers(matchers) => {
                for matcher in matchers {
                    self.cxx.push(matcher);
                }
            }
        }
        self.enabled = true;
        Ok(())
    }
}

fn parse_wip<'input>(input: &mut &'input BStr) -> winnow::Result<ExportSymbolList<'input>> {
    let mut out = ExportSymbolList::default();

    skip_comments_and_whitespace(input)?;

    if input.starts_with(b"{") {
        '{'.parse_next(input)?;
    }

    loop {
        skip_comments_and_whitespace(input)?;

        if input.starts_with(b"}") {
            '}'.parse_next(input)?;
            if input.starts_with(b";") {
                ';'.parse_next(input)?;
            }
            skip_comments_and_whitespace(input)?;
            break;
        }

        let matcher = parse_matcher(input, false)?;

        match matcher {
            ParsedSymbolMatcher::Single(single) => {
                out.general.push(single);
            }
            ParsedSymbolMatcher::CxxMatchers(matchers) => {
                for matcher in matchers {
                    out.cxx.push(matcher);
                }
            }
        }
        out.enabled = true;
    }

    Ok(out)
}

// fn parse_matcher<'data>(input: &mut &'data BStr) -> winnow::Result<SymbolMatcher<'data>> {
//     let token = take_until(1.., b';')
//         .parse_next(input)
//         .unwrap_or_else(|_: winnow::error::ContextError| input);

//     skip_comments_and_whitespace(input)?;

//     if input.starts_with(b";") {
//         ";".parse_next(input)?;
//     }

//     let token = token.trim_ascii_end();

//     Ok(
//         if let Some(unquoted) = token
//             .strip_prefix(b"\"")
//             .and_then(|t| t.strip_suffix(b"\""))
//         {
//             SymbolMatcher::Exact(unquoted)
//         } else if token.contains(&b'\\') {
//             return Err(ContextError::from_external_error(
//                 input,
//                 VersionScriptError::GlobWithQuote,
//             ));
//         } else if token == b"*" {
//             SymbolMatcher::MatchesAll
//         } else if b"[]?*".iter().any(|c| token.contains(c)) {
//             let pattern = Pattern::new(str::from_utf8(token).map_err(|_| {
//                 ContextError::from_external_error(input, VersionScriptError::InvalidUtf8String)
//             })?)
//             .map_err(|_: glob::PatternError| {
//                 ContextError::from_external_error(input, VersionScriptError::InvalidGlobPattern)
//             })?;

//             if token.contains(&b'*') {
//                 SymbolMatcher::StarGlob(pattern)
//             } else {
//                 SymbolMatcher::NonstarGlob(pattern)
//             }
//         } else {
//             SymbolMatcher::Exact(token)
//         },
//     )
// }

fn parse_matcher<'data>(
    input: &mut &'data BStr,
    from_arg: bool,
) -> winnow::Result<ParsedSymbolMatcher<'data>> {
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

            let matcher = parse_matcher(input, from_arg)?;
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

    // TODO: This is the only significant divergence between `parse_matcher` between this file and version_script.rs
    // Symbols passed to `--export-dynamic-symbol` don't end with `;`
    let token = if from_arg {
        &input
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

#[derive(Debug)]
enum VersionScriptError {
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
            VersionScriptError::UnexpectedExternCxx => {
                write!(f, "Unexpected extern \"C++\" in parsing")
            }
        }
    }
}
