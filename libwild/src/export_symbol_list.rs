use crate::error;
use crate::error::Result;
use crate::hash::PreHashed;
use crate::input_data::ExportListData;
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
    pub(crate) fn parse(data: ExportListData<'data>) -> Result<Self> {
        parse_wip
            .parse(BStr::new(data.raw))
            .map_err(|err| error!("Failed to parse symbol export list:\n{err}"))
    }

    // Based on Version Script counterpart
    pub(crate) fn contains(&self, name: &PreHashed<UnversionedSymbolName>) -> bool {
        let mut lookup_name = SymbolLookupNameWrapper::from_name(name);

        if self.general.matches_exact(&mut lookup_name, false)
            || self.cxx.matches_exact(&mut lookup_name, true)
        {
            return true;
        }

        for &non_star in &[true, false] {
            if self.general.matches_glob(&mut lookup_name, non_star, false)
                || self.cxx.matches_glob(&mut lookup_name, non_star, true)
            {
                return true;
            }
        }

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
                    ExportSymbolListError::UnexpectedExternCxx,
                ));
            };

            matchers.push(matcher);
        }

        return Ok(ParsedSymbolMatcher::CxxMatchers(matchers));
    }

    // TODO: This is the only significant divergence between `parse_matcher` from this file and version_script.rs
    // Symbols passed with `--export-dynamic-symbol=` don't end with a colon
    let token = if from_arg {
        // TODO: Clippy bug
        #[allow(clippy::needless_borrow)]
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
                ExportSymbolListError::GlobWithQuote,
            ));
        } else if token == b"*" {
            SymbolMatcher::MatchesAll
        } else if b"[]?*".iter().any(|c| token.contains(c)) {
            let pattern = Pattern::new(str::from_utf8(token).map_err(|_| {
                ContextError::from_external_error(input, ExportSymbolListError::InvalidUtf8String)
            })?)
            .map_err(|_: glob::PatternError| {
                ContextError::from_external_error(input, ExportSymbolListError::InvalidGlobPattern)
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
enum ExportSymbolListError {
    InvalidUtf8String,
    InvalidGlobPattern,
    GlobWithQuote,
    UnexpectedExternCxx,
}

impl std::error::Error for ExportSymbolListError {}

impl std::fmt::Display for ExportSymbolListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportSymbolListError::InvalidGlobPattern => write!(f, "Invalid glob pattern"),
            ExportSymbolListError::GlobWithQuote => write!(f, "Globs with quote are unsupported"),
            ExportSymbolListError::InvalidUtf8String => write!(f, "Invalid utf-8 string"),
            ExportSymbolListError::UnexpectedExternCxx => {
                write!(f, "Unexpected extern \"C++\" in parsing")
            }
        }
    }
}
