//! Rules for helping determine how we're going to lay out the output file.

use crate::OutputSections;
use crate::alignment;
use crate::ensure;
use crate::error::Result;
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
use crate::platform::SectionFlags;
use crate::platform::SectionType;
use glob::Pattern;
use hashbrown::HashTable;
use linker_utils::elf::secnames;
use std::mem::replace;

pub(crate) struct LayoutRules<'data> {
    pub(crate) section_rules: SectionRules<'data>,
}

#[derive(Default)]
pub(crate) struct LayoutRulesBuilder<'data> {
    rules: Vec<SectionRule<'data>>,
}

#[derive(Debug, Clone, Copy)]
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

/// A rule for determining what should be done with some input sections.
#[derive(Debug, Clone)]
pub(crate) struct SectionRule<'data> {
    /// The name that the section needs to have in order for this rule to match, or if `is_prefix`
    /// is true, then the prefix of the section name required.
    name: &'data [u8],

    /// Whether the section name is allowed to extend beyond what's in `name`.
    is_prefix: bool,

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

    const fn keep(section_id: OutputSectionId) -> Self {
        Self {
            section_id,
            must_keep: true,
        }
    }
}

impl<'data> LayoutRulesBuilder<'data> {
    /// Records information about any sections and symbols declared by the linker script.
    pub(crate) fn process_linker_script(
        &mut self,
        input: &InputLinkerScript<'data>,
        output_sections: &mut OutputSections<'data>,
    ) -> Result<ProcessedLinkerScript<'data>> {
        let mut symbol_defs = Vec::new();

        for cmd in &input.script.commands {
            if let linker_script::Command::Provide(provide) = cmd {
                let value_str = std::str::from_utf8(provide.value)
                    .map_err(|_| crate::error!("Invalid UTF-8 in PROVIDE symbol value"))?;

                let placement = crate::parsing::parse_symbol_expression(value_str).to_placement();
                symbol_defs.push(if provide.hidden {
                    crate::parsing::InternalSymDefInfo::hidden(placement, provide.name)
                } else {
                    crate::parsing::InternalSymDefInfo::notype(placement, provide.name)
                });
            } else if let linker_script::Command::SymbolDefinition { name, value } = cmd {
                let value_str = std::str::from_utf8(value)
                    .map_err(|_| crate::error!("Invalid UTF-8 in symbol value"))?;

                let placement = crate::parsing::parse_symbol_expression(value_str).to_placement();
                symbol_defs.push(crate::parsing::InternalSymDefInfo::notype(placement, name));
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
                                            InternalSymDefInfo::notype(
                                                SymbolPlacement::SectionEnd(id),
                                                assignment.name,
                                            )
                                        } else {
                                            InternalSymDefInfo::notype(
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

                                        symbol_defs.push(if provide.hidden {
                                            InternalSymDefInfo::hidden(placement, provide.name)
                                        } else {
                                            InternalSymDefInfo::notype(placement, provide.name)
                                        });
                                    }
                                }
                            }
                        }
                        SectionCommand::SetLocation(new_location) => location = Some(*new_location),
                        SectionCommand::Align(a) => extra_min_alignment = *a,
                    }
                }
            }
        }

        Ok(ProcessedLinkerScript {
            symbol_defs,
            input: InputRef {
                file: input.input_file,
                entry: None,
            },
        })
    }

    pub(crate) fn build(mut self) -> LayoutRules<'data> {
        let section_rules = if self.rules.is_empty() {
            SectionRules::from_rules(BUILT_IN_RULES)
        } else {
            // Even when we have a linker script, we still need to map .comment to .comment. It's a
            // special section because both input objects and the linker write to it. At least for
            // linkers that put their version in the .comment section. GNU ld doesn't, but LLD does
            // and still does so even when a linker script supposedly suppresses built-in rules.
            self.rules.push(SectionRule::exact_section_keep(
                secnames::COMMENT_SECTION_NAME,
                output_section_id::COMMENT,
            ));

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
            .map(|p| {
                let s = std::str::from_utf8(p)
                    .map_err(|_| crate::error!("Invalid UTF-8 in input file pattern"))?;
                Pattern::new(s).map_err(|_| crate::error!("Invalid glob pattern '{}'", s))
            })
            .transpose()?;

        if let Some(prefix) = pattern.strip_suffix(b"*") {
            Ok(Self {
                name: prefix,
                is_prefix: true,
                input_file_pattern: compiled_file_pattern,
                outcome,
            })
        } else {
            ensure!(
                !pattern.contains(&b'*'),
                "Wildcards are only supported at the end, found '{}'",
                String::from_utf8_lossy(pattern)
            );

            Ok(Self {
                name: pattern,
                is_prefix: false,
                input_file_pattern: compiled_file_pattern,
                outcome,
            })
        }
    }

    #[inline(always)]
    fn matches(&self, section_name: &[u8], file_name: Option<&[u8]>) -> bool {
        let section_matches = if self.is_prefix {
            section_name.starts_with(self.name)
        } else {
            section_name == self.name
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

    const fn exact_section(name: &'data [u8], section_id: OutputSectionId) -> SectionRule<'data> {
        Self::exact(
            name,
            SectionRuleOutcome::Section(SectionOutputInfo::regular(section_id)),
        )
    }

    const fn exact_section_keep(
        name: &'data [u8],
        section_id: OutputSectionId,
    ) -> SectionRule<'data> {
        Self::exact(
            name,
            SectionRuleOutcome::Section(SectionOutputInfo::keep(section_id)),
        )
    }

    const fn prefix_section(name: &'data [u8], section_id: OutputSectionId) -> SectionRule<'data> {
        Self::prefix(
            name,
            SectionRuleOutcome::Section(SectionOutputInfo::regular(section_id)),
        )
    }

    const fn prefix_section_sort(
        name: &'data [u8],
        section_id: OutputSectionId,
    ) -> SectionRule<'data> {
        Self::prefix(
            name,
            SectionRuleOutcome::SortedSection(SectionOutputInfo::keep(section_id)),
        )
    }

    const fn exact(name: &'data [u8], outcome: SectionRuleOutcome) -> SectionRule<'data> {
        SectionRule {
            name,
            is_prefix: false,
            input_file_pattern: None,
            outcome,
        }
    }

    const fn prefix(name: &'data [u8], outcome: SectionRuleOutcome) -> SectionRule<'data> {
        SectionRule {
            name,
            is_prefix: true,
            input_file_pattern: None,
            outcome,
        }
    }
}

const BUILT_IN_RULES: &[SectionRule<'static>] = &[
    SectionRule::exact_section_keep(secnames::INIT_SECTION_NAME, output_section_id::INIT),
    SectionRule::exact_section_keep(secnames::FINI_SECTION_NAME, output_section_id::FINI),
    SectionRule::exact_section_keep(
        secnames::PREINIT_ARRAY_SECTION_NAME,
        output_section_id::PREINIT_ARRAY,
    ),
    SectionRule::exact_section_keep(secnames::COMMENT_SECTION_NAME, output_section_id::COMMENT),
    SectionRule::exact_section_keep(
        secnames::NOTE_ABI_TAG_SECTION_NAME,
        output_section_id::NOTE_ABI_TAG,
    ),
    SectionRule::exact_section(
        secnames::NOTE_GNU_BUILD_ID_SECTION_NAME,
        output_section_id::NOTE_GNU_BUILD_ID,
    ),
    SectionRule::prefix_section(secnames::RODATA_SECTION_NAME, output_section_id::RODATA),
    SectionRule::prefix_section(secnames::TEXT_SECTION_NAME, output_section_id::TEXT),
    SectionRule::prefix_section(
        secnames::DATA_REL_RO_SECTION_NAME,
        output_section_id::DATA_REL_RO,
    ),
    SectionRule::prefix_section(secnames::DATA_SECTION_NAME, output_section_id::DATA),
    SectionRule::prefix_section(secnames::BSS_SECTION_NAME, output_section_id::BSS),
    SectionRule::prefix_section_sort(
        secnames::INIT_ARRAY_SECTION_NAME,
        output_section_id::INIT_ARRAY,
    ),
    SectionRule::prefix_section_sort(secnames::CTORS_SECTION_NAME, output_section_id::INIT_ARRAY),
    SectionRule::prefix_section_sort(
        secnames::FINI_ARRAY_SECTION_NAME,
        output_section_id::FINI_ARRAY,
    ),
    SectionRule::prefix_section_sort(secnames::DTORS_SECTION_NAME, output_section_id::FINI_ARRAY),
    SectionRule::prefix_section(secnames::TDATA_SECTION_NAME, output_section_id::TDATA),
    SectionRule::prefix_section(secnames::TBSS_SECTION_NAME, output_section_id::TBSS),
    SectionRule::prefix_section(
        secnames::GCC_EXCEPT_TABLE_SECTION_NAME,
        output_section_id::GCC_EXCEPT_TABLE,
    ),
    SectionRule::prefix(b".rela", SectionRuleOutcome::Discard),
    SectionRule::prefix(b".crel", SectionRuleOutcome::Discard),
    SectionRule::exact(b".note.GNU-stack", SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::STRTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::SYMTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::SHSTRTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::GROUP_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::EH_FRAME_SECTION_NAME, SectionRuleOutcome::EhFrame),
    SectionRule::exact(
        secnames::SFRAME_SECTION_NAME,
        SectionRuleOutcome::Section(SectionOutputInfo::keep(output_section_id::SFRAME)),
    ),
    SectionRule::exact(
        secnames::NOTE_GNU_PROPERTY_SECTION_NAME,
        SectionRuleOutcome::NoteGnuProperty,
    ),
    SectionRule::exact(
        secnames::RISCV_ATTRIBUTES_SECTION_NAME,
        SectionRuleOutcome::RiscVAttribute,
    ),
    SectionRule::prefix(b".debug_", SectionRuleOutcome::Debug),
];

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
            let hash = section_name_prefix_hash(rule.name)
                .expect("Prefixes of length less than 4 not yet supported");

            map.rules.insert_unique(hash, rule.clone(), |existing| {
                section_name_prefix_hash(existing.name).unwrap_or(0)
            });
        }

        map
    }

    #[inline(always)]
    pub(crate) fn lookup(
        &self,
        section_name: &[u8],
        file_name: Option<&[u8]>,
        section_flags: impl SectionFlags,
        sh_type: impl SectionType,
    ) -> SectionRuleOutcome {
        if section_flags.should_exclude() {
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
            return unnamed_section_output(section_flags, sh_type);
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
fn unnamed_section_output(
    section_flags: impl SectionFlags,
    sh_type: impl SectionType,
) -> SectionRuleOutcome {
    if !section_flags.is_alloc() {
        SectionRuleOutcome::Discard
    } else if sh_type.is_prog_bits() {
        if section_flags.is_executable() {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::TEXT))
        } else if section_flags.is_tls() {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::TDATA))
        } else if section_flags.is_writable() {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::DATA))
        } else {
            SectionRuleOutcome::Section(SectionOutputInfo::regular(output_section_id::RODATA))
        }
    } else if sh_type.is_no_bits() {
        if section_flags.is_tls() {
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
    let rules = SectionRules::from_rules(BUILT_IN_RULES);
    let lookup_name = |name: &str| {
        rules.lookup(
            name.as_bytes(),
            None,
            linker_utils::elf::SectionFlags::empty(),
            linker_utils::elf::SectionType::from_u32(0),
        )
    };

    assert_eq!(
        lookup_name(".comment"),
        SectionRuleOutcome::Section(SectionOutputInfo {
            section_id: output_section_id::COMMENT,
            must_keep: true
        })
    );
}
