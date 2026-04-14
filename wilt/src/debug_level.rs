//! Debug-info fidelity levels. Mirrors Rust's `-C debuginfo=N`.
//!
//! See `wilt-debug-info-plan.md` for the full tiered design. Phase 1
//! implements `None` and `Names` honestly; `Lines` and `Full` fall
//! back to the highest honest tier until later phases wire them up.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebugLevel {
    /// Strip DWARF, source maps, names, target_features. Smallest
    /// output. Matches `wasm-opt -O --strip-debug`'s effective policy.
    None,
    /// Preserve and rewrite the `name` section to stay consistent
    /// with the output's function-index layout. DWARF + source-maps
    /// still stripped (too stale to be useful without Phase 2).
    Names,
    /// As `Names` plus `.debug_line` rewritten to point at the
    /// output's code. Phase 2 implementation. Today falls back to
    /// `Names`.
    Lines,
    /// As `Lines` plus `.debug_info` / `.debug_str` / … rewritten.
    /// Phase 3. Today falls back to whatever is implemented.
    Full,
}

impl DebugLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" | "0" | "off" => Some(Self::None),
            "names" | "1" => Some(Self::Names),
            "lines" | "2" | "line-tables" => Some(Self::Lines),
            "full" | "3" | "all" => Some(Self::Full),
            _ => None,
        }
    }

    /// The highest tier that is fully implemented today. Callers who
    /// asked for a higher tier silently fall back to this.
    pub fn highest_implemented() -> Self { Self::Lines }

    pub fn implemented_floor(self) -> Self {
        match self {
            Self::None => Self::None,
            _ => {
                let cap = Self::highest_implemented();
                if self.rank() <= cap.rank() { self } else { cap }
            }
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Names => 1,
            Self::Lines => 2,
            Self::Full => 3,
        }
    }
}

impl Default for DebugLevel {
    /// The default policy: highest implemented tier. Today: `Names`.
    /// When Phase 2 lands this silently upgrades to `Lines` without
    /// callers changing anything.
    fn default() -> Self { Self::highest_implemented() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_aliases() {
        assert_eq!(DebugLevel::parse("none"), Some(DebugLevel::None));
        assert_eq!(DebugLevel::parse("0"), Some(DebugLevel::None));
        assert_eq!(DebugLevel::parse("names"), Some(DebugLevel::Names));
        assert_eq!(DebugLevel::parse("1"), Some(DebugLevel::Names));
        assert_eq!(DebugLevel::parse("line-tables"), Some(DebugLevel::Lines));
        assert_eq!(DebugLevel::parse("3"), Some(DebugLevel::Full));
        assert_eq!(DebugLevel::parse("garbage"), None);
    }

    #[test]
    fn implemented_floor_caps_at_lines_today() {
        assert_eq!(DebugLevel::None.implemented_floor(), DebugLevel::None);
        assert_eq!(DebugLevel::Names.implemented_floor(), DebugLevel::Names);
        assert_eq!(DebugLevel::Lines.implemented_floor(), DebugLevel::Lines);
        assert_eq!(DebugLevel::Full.implemented_floor(), DebugLevel::Lines);
    }
}
