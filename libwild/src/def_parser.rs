use crate::error;
use crate::error::Result;
use crate::hash::PreHashed;
use crate::symbol::UnversionedSymbolName;
use crate::{
    input_data::VersionScriptData,
    linker_script::skip_comments_and_whitespace,
    version_script::{BasicMatchRules, SymbolMatcher},
};
use glob::Pattern;
use winnow::{
    BStr, Parser,
    error::{ContextError, FromExternalError as _},
    token::take_until,
};

#[derive(Default)]
pub(crate) struct ExportSymbolList<'data> {
    pub(crate) enabled: bool,
    pub(crate) symbols: BasicMatchRules<'data>,
}

impl<'data> ExportSymbolList<'data> {
    pub(crate) fn parse(data: VersionScriptData<'data>) -> Result<Self> {
        parse_wip
            .parse(BStr::new(data.raw))
            .map_err(|err| error!("Failed to parse version script:\n{err}"))
    }

    pub(crate) fn contains(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        if self.symbols.matches_all {
            return true;
        }
        if self.symbols.exact.contains(name) {
            return true;
        }
        let name_str = str::from_utf8(name.bytes()).unwrap_or_else(|_| {
            panic!(
                "Valid utf-8 identifier expected: {}",
                String::from_utf8_lossy(name.bytes())
            )
        });
        if self
            .symbols
            .nonstar_globs
            .iter()
            .any(|glob| glob.matches(name_str))
        {
            return true;
        }
        if self
            .symbols
            .star_globs
            .iter()
            .any(|glob| glob.matches(name_str))
        {
            return true;
        }
        false
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn add_symbol(&mut self, symbol: &'data str) -> Result<()> {
        let matcher = parse_matcher(&mut BStr::new(symbol))?;
        self.symbols.push(matcher);
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

        let matcher = parse_matcher(input)?;

        out.symbols.push(matcher);
        out.enabled = true;
    }

    Ok(out)
}

fn parse_matcher<'data>(input: &mut &'data BStr) -> winnow::Result<SymbolMatcher<'data>> {
    let token = take_until(1.., b';')
        .parse_next(input)
        .unwrap_or_else(|_: winnow::error::ContextError| input);

    skip_comments_and_whitespace(input)?;

    if input.starts_with(b";") {
        ";".parse_next(input)?;
    }

    let token = token.trim_ascii_end();

    Ok(
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
    )
}

#[derive(Debug)]
enum VersionScriptError {
    InvalidUtf8String,
    InvalidGlobPattern,
    GlobWithQuote,
}

impl std::error::Error for VersionScriptError {}

impl std::fmt::Display for VersionScriptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VersionScriptError::InvalidGlobPattern => write!(f, "Invalid glob pattern"),
            VersionScriptError::GlobWithQuote => write!(f, "Globs with quote are unsupported"),
            VersionScriptError::InvalidUtf8String => write!(f, "Invalid utf-8 string"),
        }
    }
}
