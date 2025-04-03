//! Rules for helping determine how we're going to lay out the output file.

use crate::elf::SectionHeader;
use crate::hash::hash_bytes;
use crate::output_section_id;
use crate::output_section_id::OutputSectionId;
use hashbrown::HashTable;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use linker_utils::elf::secnames;
use linker_utils::elf::shf;
use linker_utils::elf::sht;

/// Rules governing how input sections should be mapped to output sections.
pub(crate) struct SectionRules<'data> {
    /// Rules by the hash of the first 4 bytes of the name.
    rules: HashTable<SectionRule<'data>>,
}

/// A rule for determining what should be done with some input sections.
#[derive(Debug, Clone, Copy)]
struct SectionRule<'data> {
    /// The name that the section needs to have in order for this rule to match, or if `is_prefix`
    /// is true, then the prefix of the section name required.
    name: &'data [u8],

    /// Whether the section name is allowed to extend beyond what's in `name`.
    is_prefix: bool,

    /// What to do if the rule matches.
    outcome: SectionRuleOutcome,
}

/// What should be done with a particular input section.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SectionRuleOutcome {
    Section(OutputSectionId),
    Discard,
    Custom,
    EhFrame,
    NoteGnuProperty,
    Debug,
}

impl<'data> SectionRule<'data> {
    #[inline(always)]
    fn matches(&self, section_name: &[u8]) -> bool {
        if self.is_prefix {
            section_name.starts_with(self.name)
        } else {
            section_name == self.name
        }
    }

    const fn exact_section(name: &'data [u8], section_id: OutputSectionId) -> SectionRule<'data> {
        Self::exact(name, SectionRuleOutcome::Section(section_id))
    }

    const fn prefix_section(name: &'data [u8], section_id: OutputSectionId) -> SectionRule<'data> {
        Self::prefix(name, SectionRuleOutcome::Section(section_id))
    }

    const fn exact(name: &'data [u8], outcome: SectionRuleOutcome) -> SectionRule<'data> {
        SectionRule {
            name,
            is_prefix: false,
            outcome,
        }
    }

    const fn prefix(name: &'data [u8], outcome: SectionRuleOutcome) -> SectionRule<'data> {
        SectionRule {
            name,
            is_prefix: true,
            outcome,
        }
    }
}

const BUILT_IN_RULES: &[SectionRule<'static>] = &[
    SectionRule::exact_section(secnames::INIT_SECTION_NAME, output_section_id::INIT),
    SectionRule::exact_section(secnames::FINI_SECTION_NAME, output_section_id::FINI),
    SectionRule::exact_section(
        secnames::PREINIT_ARRAY_SECTION_NAME,
        output_section_id::PREINIT_ARRAY,
    ),
    SectionRule::exact_section(secnames::COMMENT_SECTION_NAME, output_section_id::COMMENT),
    SectionRule::exact_section(
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
    SectionRule::prefix_section(
        secnames::INIT_ARRAY_SECTION_NAME,
        output_section_id::INIT_ARRAY,
    ),
    SectionRule::prefix_section(b".ctors", output_section_id::INIT_ARRAY),
    SectionRule::prefix_section(
        secnames::FINI_ARRAY_SECTION_NAME,
        output_section_id::FINI_ARRAY,
    ),
    SectionRule::prefix_section(b".dtors", output_section_id::FINI_ARRAY),
    SectionRule::prefix_section(secnames::TDATA_SECTION_NAME, output_section_id::TDATA),
    SectionRule::prefix_section(secnames::TBSS_SECTION_NAME, output_section_id::TBSS),
    SectionRule::prefix_section(
        secnames::GCC_EXCEPT_TABLE_SECTION_NAME,
        output_section_id::GCC_EXCEPT_TABLE,
    ),
    SectionRule::prefix(b".rela", SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::STRTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::SYMTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::SHSTRTAB_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::GROUP_SECTION_NAME, SectionRuleOutcome::Discard),
    SectionRule::exact(secnames::EH_FRAME_SECTION_NAME, SectionRuleOutcome::EhFrame),
    SectionRule::exact(
        secnames::NOTE_GNU_PROPERTY_SECTION_NAME,
        SectionRuleOutcome::NoteGnuProperty,
    ),
    SectionRule::prefix(b".debug_", SectionRuleOutcome::Debug),
];

/// Multiplier for the rule-hashtable's capacity, relative to the number of entries. We want a
/// relatively sparse hashtable, since we may have a small number of entries with the same prefix
/// and thus the same hash. Also, during lookup, if there's no rule with a matching prefix, we want
/// to increase the chances of hitting an empty slot straight away. Experimentally, at least with
/// the built-in rules, multipliers larger than 2 don't further reduce the number of comparisons.
const RULE_TABLE_CAPACITY_MULTIPLIER: usize = 2;

impl Default for SectionRules<'_> {
    fn default() -> Self {
        Self::from_rules(BUILT_IN_RULES)
    }
}

impl<'data> SectionRules<'data> {
    fn from_rules(rules: &[SectionRule<'data>]) -> Self {
        let mut map = SectionRules {
            rules: HashTable::with_capacity(rules.len() * RULE_TABLE_CAPACITY_MULTIPLIER),
        };
        for rule in rules {
            let hash = section_name_prefix_hash(rule.name)
                .expect("Prefixes of length less than 4 not yet supported");

            map.rules.insert_unique(hash, *rule, |existing| {
                section_name_prefix_hash(existing.name).unwrap_or(0)
            });
        }

        map
    }

    #[inline(always)]
    pub(crate) fn lookup(
        &self,
        section_name: &[u8],
        section_flags: SectionFlags,
        section: &SectionHeader,
    ) -> SectionRuleOutcome {
        if let Some(hash) = section_name_prefix_hash(section_name) {
            if let Some(rule) = self.rules.find(hash, |rule| rule.matches(section_name)) {
                return rule.outcome;
            }
        }

        if section_name.is_empty() {
            let sh_type = SectionType::from_header(section);
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
fn unnamed_section_output(section_flags: SectionFlags, sh_type: SectionType) -> SectionRuleOutcome {
    if !section_flags.contains(shf::ALLOC) {
        SectionRuleOutcome::Discard
    } else if sh_type == sht::PROGBITS {
        if section_flags.contains(shf::EXECINSTR) {
            SectionRuleOutcome::Section(output_section_id::TEXT)
        } else if section_flags.contains(shf::TLS) {
            SectionRuleOutcome::Section(output_section_id::TDATA)
        } else if section_flags.contains(shf::WRITE) {
            SectionRuleOutcome::Section(output_section_id::DATA)
        } else {
            SectionRuleOutcome::Section(output_section_id::RODATA)
        }
    } else if sh_type == sht::NOBITS {
        if section_flags.contains(shf::TLS) {
            SectionRuleOutcome::Section(output_section_id::TBSS)
        } else {
            SectionRuleOutcome::Section(output_section_id::BSS)
        }
    } else {
        SectionRuleOutcome::Discard
    }
}
