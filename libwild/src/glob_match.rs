use glob::Pattern;
use std::str;
pub(crate) enum GlobPatternType {
    Exact,
    EscapedExact,
    Star,
    NonStar,
}

pub(crate) fn analyze_glob_pattern(pattern: &[u8]) -> GlobPatternType {
    // Fast path for when none of the characters are present.
    if memchr::memchr3(b'*', b'?', b'\\', pattern).is_none()
        && memchr::memchr2(b'[', b']', pattern).is_none()
    {
        return GlobPatternType::Exact;
    }

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
pub(crate) fn unescape_pattern(pattern: &[u8]) -> Vec<u8> {
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

pub(crate) fn compile_glob_pattern(token: &[u8]) -> Result<Pattern, &str> {
    let pattern = str::from_utf8(token).map_err(|_| "Invalid UTF-8 string")?;
    // Right now, there is a pending PR that will support the '^' as the negation
    // character in the glob crate: https://github.com/rust-lang/glob/issues/116
    //
    // Let's optimistically assume the '^' cannot be part of the symbol's name (escaped
    // in a pattern).
    let pattern = pattern.replace("[^", "[!");
    Pattern::new(pattern.as_str()).map_err(|_| "Invalid Glob Pattern")
}
