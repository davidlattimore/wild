//! Rules for helping determine how we're going to lay out the output file.

use crate::OutputSections;
use crate::alignment;
use crate::error::Result;
use crate::glob_match::GlobPatternType;
use crate::glob_match::analyze_glob_pattern;
use crate::glob_match::compile_glob_pattern;
use crate::glob_match::unescape_pattern;
use crate::hash::hash_bytes;
use crate::input_data::InputLinkerScript;
use crate::input_data::InputRef;
use crate::linker_script;
use crate::linker_script::ContentsCommand;
use crate::linker_script::SectionCommand;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::SectionName;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::ProcessedLinkerScript;
use crate::parsing::SymbolPlacement;
use crate::platform::Platform;
use crate::platform::SectionHeader;
use glob::Pattern;
use hashbrown::HashTable;
use std::borrow::Cow;
use linker_utils::elf::secnames;
use std::mem::replace;

pub(crate) struct LayoutRules<'data> {
    pub(crate) section_rules: SectionRules<'data>,
}

#[derive(Default)]
pub(crate) struct LayoutRulesBuilder<'data> {
    rules: Vec<SectionRule<'data>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionKind<'data> {
    /// This is the primary section.
    Primary(SectionName<'data>),

    /// This is a secondary section that will be merged into the primary. The ID of the primary is
    /// supplied.
    Secondary(OutputSectionId),
}

/// Rules governing how input sections should be mapped to output sections.
pub(crate) struct SectionRules<'data> {
    /// Rules by the hash of the first 4 bytes of the name.
    rules: HashTable<SectionRule<'data>>,
}

/// Determines how a section name pattern is matched against input section names.
#[derive(Debug, Clone)]
pub(crate) enum SectionNameMatcher<'data> {
    /// Matches sections whose name is exactly equal to the stored bytes.
    Exact(Cow<'data, [u8]>),

    /// Matches sections whose name starts with the stored bytes.
    Prefix(&'data [u8]),

    /// Matches sections whose name matches the glob pattern. The byte slice is the
    /// literal prefix used as hash table key.
    Glob(&'data [u8], Pattern),
}

/// Return the literal byte prefix of this matcher, used for hash table keying.
impl<'data> SectionNameMatcher<'data> {
    fn prefix_bytes(&self) -> &[u8] {
        match self {
            Self::Exact(n) => n.as_ref(),
            Self::Prefix(n) | Self::Glob(n, _) => n,
        }
    }
}

/// A rule for determining what should be done with some input sections.
#[derive(Debug, Clone)]
pub(crate) struct SectionRule<'data> {
    /// Determine how the section rule matches against input section names.
    name_matcher: SectionNameMatcher<'data>,

    /// Pre-compiled glob pattern for matching input filenames. `None` means the rule matches all
    /// files.
    input_file_pattern: Option<Pattern>,

    /// What to do if the rule matches.
    outcome: SectionRuleOutcome,
}

/// What should be done with a particular input section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SectionRuleOutcome {
    Section(SectionOutputInfo),
    Discard,
    Custom,
    EhFrame,
    NoteGnuProperty,
    NoteGnuStack,
    Debug,
    RiscVAttribute,
    SortedSection(SectionOutputInfo),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SectionOutputInfo {
    pub(crate) section_id: OutputSectionId,
    pub(crate) must_keep: bool,
}

impl SectionOutputInfo {
    const fn regular(section_id: OutputSectionId) -> Self {
        Self {
            section_id,
            must_keep: false,
        }
    }

    pub(crate) const fn keep(section_id: OutputSectionId) -> Self {
        Self {
            section_id,
            must_keep: true,
        }
    }
}

impl<'data> LayoutRulesBuilder<'data> {
    /// Records information about any sections and symbols declared by the linker script.
    pub(crate) fn process_linker_script<P: Platform>(
        &mut self,
        input: &InputLinkerScript<'data>,
        output_sections: &mut OutputSections<'data, P>,
    ) -> Result<ProcessedLinkerScript<'data>> {
        let mut symbol_defs = Vec::new();
        let mut assertions = Vec::new();

        for cmd in &input.script.commands {
            if let linker_script::Command::Provide(provide) = cmd {
                let value_str = std::str::from_utf8(provide.value)
                    .map_err(|_| crate::error!("Invalid UTF-8 in PROVIDE symbol value"))?;

                let placement = crate::parsing::parse_symbol_expression(value_str).to_placement();
                symbol_defs.push(
                    crate::parsing::InternalSymDefInfo::new(placement, provide.name)
                        .with_hidden(provide.hidden),
                );
            } else if let linker_script::Command::SymbolDefinition { name, value } = cmd {
                let value_str = std::str::from_utf8(value)
                    .map_err(|_| crate::error!("Invalid UTF-8 in symbol value"))?;

                let placement = crate::parsing::parse_symbol_expression(value_str).to_placement();
                symbol_defs.push(crate::parsing::InternalSymDefInfo::new(placement, name));
            } else if let linker_script::Command::Sections(sections) = cmd {
                let mut location = None;

                // "Extra alignment" is what we call it when a linker script sets alignment via a
                // command like `. = ALIGN(8)`. We attach that to the subsequent section by
                // adjusting its alignment. This doesn't exactly match what GNU ld does, since what
                // we do can cause the alignment of the section in the section headers to increase,
                // whereas GNU ld leaves the section header alignment alone in this case. For now,
                // though, it doesn't seem worthwhile having two separate alignment properties on a
                // section, one of which doesn't affect the header value.
                let mut extra_min_alignment = alignment::MIN;

                for sec_cmd in &sections.commands {
                    match sec_cmd {
                        SectionCommand::Section(sec) => {
                            let min_alignment = sec
                                .alignment
                                .unwrap_or(alignment::MIN)
                                .max(replace(&mut extra_min_alignment, alignment::MIN));

                            let primary_section_id = output_sections.add_named_section(
                                SectionName(sec.output_section_name),
                                min_alignment,
                                location.take(),
                            );

                            let mut last_section_id = None;

                            for contents_cmd in &sec.commands {
                                match contents_cmd {
                                    ContentsCommand::Matcher(matcher) => {
                                        let section_id = if last_section_id.is_none() {
                                            primary_section_id
                                        } else {
                                            output_sections.add_secondary_section(
                                                primary_section_id,
                                                replace(&mut extra_min_alignment, alignment::MIN),
                                                None,
                                            )
                                        };

                                        for pattern in &matcher.input_section_name_patterns {
                                            self.add_section_rule(SectionRule::new(
                                                pattern,
                                                matcher.input_file_pattern,
                                                crate::layout_rules::SectionRuleOutcome::Section(
                                                    SectionOutputInfo {
                                                        section_id,
                                                        must_keep: matcher.must_keep,
                                                    },
                                                ),
                                            )?);
                                        }

                                        last_section_id = Some(section_id);
                                    }
                                    ContentsCommand::SymbolAssignment(assignment) => {
                                        symbol_defs.push(if let Some(id) = last_section_id {
                                            InternalSymDefInfo::new(
                                                SymbolPlacement::SectionEnd(id),
                                                assignment.name,
                                            )
                                        } else {
                                            InternalSymDefInfo::new(
                                                SymbolPlacement::SectionStart(primary_section_id),
                                                assignment.name,
                                            )
                                        });
                                    }
                                    ContentsCommand::Align(a) => extra_min_alignment = *a,
                                    ContentsCommand::Provide(provide) => {
                                        let placement = if let Some(id) = last_section_id {
                                            SymbolPlacement::SectionEnd(id)
                                        } else {
                                            SymbolPlacement::SectionStart(primary_section_id)
                                        };

                                        symbol_defs.push(
                                            InternalSymDefInfo::new(placement, provide.name)
                                                .with_hidden(provide.hidden),
                                        );
                                    }
                                }
                            }
                        }
                        SectionCommand::SetLocation(new_location) => location = Some(*new_location),
                        SectionCommand::Align(a) => extra_min_alignment = *a,
                        SectionCommand::Assert(assert_cmd) => {
                            assertions.push(assert_cmd.clone());
                        }
                    }
                }
            } else if let linker_script::Command::Assert(assert_cmd) = cmd {
                assertions.push(assert_cmd.clone());
            }
        }

        Ok(ProcessedLinkerScript {
            symbol_defs,
            assertions,
            input: InputRef {
                file: input.input_file,
                entry: None,
            },
            file_bytes: input.script_bytes,
        })
    }

    pub(crate) fn build<P: Platform>(mut self) -> LayoutRules<'data> {
        let section_rules = if self.rules.is_empty() {
            SectionRules::from_rules(P::default_layout_rules())
        } else {
            P::linker_script_rules_pre_build(&mut self);
            SectionRules::from_rules(&self.rules)
        };

        LayoutRules { section_rules }
    }

    pub(crate) fn add_section_rule(&mut self, rule: SectionRule<'data>) {
        self.rules.push(rule);
    }
}

impl<'data> SectionRule<'data> {
    pub(crate) fn new(
        pattern: &'data [u8],
        input_file_pattern: Option<&'data [u8]>,
        outcome: SectionRuleOutcome,
    ) -> Result<Self> {
        let compiled_file_pattern = input_file_pattern
            .map(|pattern| compile_glob_pattern(pattern).map_err(|e| crate::error!("{e}")))
            .transpose()?;

        let name_matcher = match analyze_glob_pattern(pattern) {
            GlobPatternType::Exact => SectionNameMatcher::Exact(Cow::Borrowed(pattern)),
            GlobPatternType::EscapedExact => {
                SectionNameMatcher::Exact(Cow::Owned(unescape_pattern(pattern)))
            }
            GlobPatternType::Star | GlobPatternType::NonStar => {
                let compiled_pattern =
                    compile_glob_pattern(pattern).map_err(|e| crate::error!("{}", e))?;

                SectionNameMatcher::Glob(pattern, compiled_pattern)
            }
        };

        Ok(Self {
            name_matcher,
            input_file_pattern: compiled_file_pattern,
            outcome,
        })
    }

    #[inline(always)]
    fn matches(&self, section_name: &[u8], file_name: Option<&[u8]>) -> bool {
        let section_matches = match &self.name_matcher {
            SectionNameMatcher::Exact(name) => section_name == name.as_ref(),
            SectionNameMatcher::Prefix(prefix) => section_name.starts_with(prefix),
            SectionNameMatcher::Glob(_, pattern) => {
                if let Ok(name_str) = std::str::from_utf8(section_name) {
                    pattern.matches(name_str)
                } else {
                    false
                }
            }
        };

        if !section_matches {
            return false;
        }

        // If the rule has no file pattern, it matches all files.
        let Some(pattern) = &self.input_file_pattern else {
            return true;
        };

        // If the caller didn't provide a filename, only match rules with no file filter.
        let Some(name) = file_name else {
            return false;
        };

        // Convert the filename bytes to a string for glob matching.
        let Ok(name_str) = std::str::from_utf8(name) else {
            return false;
        };

        pattern.matches(name_str)
    }

    pub(crate) const fn exact_section(
        name: &'data [u8],
        section_id: OutputSectionId,
    ) -> SectionRule<'data> {
        Self::exact(
            name,
            SectionRuleOutcome::Section(SectionOutputInfo::regular(section_id)),
        )
    }

    pub(crate) const fn exact_section_keep(
        name: &'data [u8],
        section_id: OutputSectionId,
    ) -> SectionRule<'data> {
        Self::exact(
            name,
            SectionRuleOutcome::Section(SectionOutputInfo::keep(section_id)),
        )
    }

    pub(crate) const fn prefix_section(
        name: &'data [u8],
        section_id: OutputSectionId,
    ) -> SectionRule<'data> {
        Self::prefix(
            name,
            SectionRuleOutcome::Section(SectionOutputInfo::regular(section_id)),
        )
    }

    pub(crate) const fn prefix_section_sort(
        name: &'data [u8],
        section_id: OutputSectionId,
    ) -> SectionRule<'data> {
        Self::prefix(
            name,
            SectionRuleOutcome::SortedSection(SectionOutputInfo::keep(section_id)),
        )
    }

    pub(crate) const fn exact(
        name: &'data [u8],
        outcome: SectionRuleOutcome,
    ) -> SectionRule<'data> {
        SectionRule {
            name_matcher: SectionNameMatcher::Exact(Cow::Borrowed(name)),
            input_file_pattern: None,
            outcome,
        }
    }

    pub(crate) const fn prefix(
        name: &'data [u8],
        outcome: SectionRuleOutcome,
    ) -> SectionRule<'data> {
        SectionRule {
            name_matcher: SectionNameMatcher::Prefix(name),
            input_file_pattern: None,
            outcome,
        }
    }
}

/// Multiplier for the rule-hashtable's capacity, relative to the number of entries. We want a
/// relatively sparse hashtable, since we may have a small number of entries with the same prefix
/// and thus the same hash. Also, during lookup, if there's no rule with a matching prefix, we want
/// to increase the chances of hitting an empty slot straight away. Experimentally, at least with
/// the built-in rules, multipliers larger than 2 don't further reduce the number of comparisons.
const RULE_TABLE_CAPACITY_MULTIPLIER: usize = 2;

impl<'data> SectionRules<'data> {
    fn from_rules(rules: &[SectionRule<'data>]) -> Self {
        let mut map = SectionRules {
            rules: HashTable::with_capacity(rules.len() * RULE_TABLE_CAPACITY_MULTIPLIER),
        };
        for rule in rules {
            let hash = section_name_prefix_hash(rule.name_matcher.prefix_bytes())
                .expect("Prefixes of length less than 4 not yet supported");

            map.rules.insert_unique(hash, rule.clone(), |existing| {
                section_name_prefix_hash(existing.name_matcher.prefix_bytes()).unwrap_or(0)
            });
        }

        map
    }

    #[inline(always)]
    pub(crate) fn lookup(
        &self,
        section_name: &[u8],
        file_name: Option<&[u8]>,
        section_header: &impl SectionHeader,
    ) -> SectionRuleOutcome {
        if section_header.should_exclude() {
            return SectionRuleOutcome::Discard;
        }

        if let Some(hash) = section_name_prefix_hash(section_name)
            && let Some(rule) = self
                .rules
                .find(hash, |rule| rule.matches(section_name, file_name))
        {
            return rule.outcome;
        }

        if section_name.is_empty() {
            return unnamed_section_output(section_header);
        }

        SectionRuleOutcome::Custom
    }

    #[inline(always)]
    pub(crate) fn lookup_for_partial_link(
        &self,
        section_name: &[u8],
        section_header: &impl SectionHeader,
    ) -> SectionRuleOutcome {
        let _ = self;
        if section_header.should_exclude() {
            return SectionRuleOutcome::Discard;
        }

        if section_name.is_empty() {
            return unnamed_section_output(section_header);
        }

        match section_name {
            secnames::STRTAB_SECTION_NAME
            | secnames::SYMTAB_SECTION_NAME
            | secnames::SHSTRTAB_SECTION_NAME
            | secnames::GROUP_SECTION_NAME => {
                return SectionRuleOutcome::Discard;
            }
            secnames::NOTE_GNU_PROPERTY_SECTION_NAME => return SectionRuleOutcome::NoteGnuProperty,
            secnames::NOTE_ABI_TAG_SECTION_NAME => {
                return SectionRuleOutcome::Section(SectionOutputInfo::keep(
                    output_section_id::NOTE_ABI_TAG,
                ));
            }
            _ => {}
        }

        if section_name.starts_with(b".rela") || section_name.starts_with(b".crel") {
            return SectionRuleOutcome::Discard;
        }

        SectionRuleOutcome::Custom
    }
}

/// Returns a hash of the first four bytes of the supplied name or `None` if the name is shorter
/// than 4 bytes.
#[inline(always)]
fn section_name_prefix_hash(name: &[u8]) -> Option<u64> {
    Some(hash_bytes(name.get(..4)?))
}

/// Determines, where if anywhere, we should place an input section with no name.
fn unnamed_section_output(section_header: &impl SectionHeader) -> SectionRuleOutcome {
    if !section_header.is_alloc() {
        SectionRuleOutcome::Discard
    } else if section_header.is_prog_bits() {
        if section_header.is_executable() {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::TEXT))
        } else if section_header.is_tls() {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::TDATA))
        } else if section_header.is_writable() {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::DATA))
        } else {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::RODATA))
        }
    } else if section_header.is_no_bits() {
        if section_header.is_tls() {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::TBSS))
        } else {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::BSS))
        }
    } else {
        SectionRuleOutcome::Discard
    }
}

#[test]
fn test_section_mapping() {
    let rules = SectionRules::from_rules(crate::elf::Elf::default_layout_rules());
    let header = crate::elf::SectionHeader {
        sh_name: Default::default(),
        sh_type: Default::default(),
        sh_flags: Default::default(),
        sh_addr: Default::default(),
        sh_offset: Default::default(),
        sh_size: Default::default(),
        sh_link: Default::default(),
        sh_info: Default::default(),
        sh_addralign: Default::default(),
        sh_entsize: Default::default(),
    };
    let lookup_name = |name: &str| rules.lookup(name.as_bytes(), None, &header);

    assert_eq!(
        lookup_name(".comment"),
        SectionRuleOutcome::Section(SectionOutputInfo {
            section_id: output_section_id::COMMENT,
            must_keep: true
        })
    );
}

#[test]
fn test_glob_section_matching() {
    let rule = SectionRule::new(b".mydata.[0-9]", None, SectionRuleOutcome::Discard).unwrap();

    assert!(rule.matches(b".mydata.0", None));
    assert!(rule.matches(b".mydata.5", None));
    assert!(!rule.matches(b".mydata.A", None));
    assert!(!rule.matches(b".mydata.10", None));
    assert!(!rule.matches(b".mydata.", None));
    assert!(!rule.matches(b".other.0", None));
}

#[test]
fn test_glob_star_anywhere() {
    let rule = SectionRule::new(b".text.*.foo", None, SectionRuleOutcome::Discard).unwrap();
    assert!(rule.matches(b".text.bar.foo", None));
    assert!(rule.matches(b".text.baz.foo", None));
    assert!(!rule.matches(b".text.bar.baz", None));
}

#[test]
fn test_glob_section_character_class() {
    let rule = SectionRule::new(b"foo[_-]bar", None, SectionRuleOutcome::Discard).unwrap();
    assert!(rule.matches(b"foo_bar", None));
    assert!(rule.matches(b"foo-bar", None));
    assert!(!rule.matches(b"foobar", None));
    assert!(!rule.matches(b"foo_barbaz", None));
    assert!(!rule.matches(b"fooxbar", None));

    // [a-z] alphabet range match
    let range_rule = SectionRule::new(b"foo[a-z]bar", None, SectionRuleOutcome::Discard).unwrap();
    assert!(range_rule.matches(b"fooabar", None));
    assert!(range_rule.matches(b"foozbar", None));
    assert!(range_rule.matches(b"foombar", None));
    assert!(!range_rule.matches(b"fooAbar", None));
    assert!(!range_rule.matches(b"foo1bar", None));

    // escaped character match
    let escape_rule = SectionRule::new(b"foo\\*bar", None, SectionRuleOutcome::Discard).unwrap();
    assert!(escape_rule.matches(b"foo*bar", None));
    assert!(!escape_rule.matches(b"fooxbar", None));
    assert!(!escape_rule.matches(b"foobar", None));
}
