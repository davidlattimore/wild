//! The code in this module is responsible for diffing the contents of sections. This is made
//! complicated due to the layouts of the binaries being different. This means that working out what
//! to diff is slightly tricky. Once we are diffing, the contents can be different because of
//! references to symbols that are in different locations in the different binaries. A high level
//! output of how this works follows.
//!
//! We depend on Wild's binary output having a corresponding .layout file. This allows us to know
//! all the input sections that Wild put into the binary and where it put them.
//!
//! We then start by looking for symbols that have exactly one definition in each binary. We can
//! then tie the input section that defined that symbol to its corresponding location in all of the
//! binaries.
//!
//! We then have an input section that came from one of the input files and the location at which
//! each linker placed that input section in their respective binaries. We can now diff the
//! different versions of the section.
//!
//! Diffing the section revolves around the relocations that the original input file listed for that
//! section. We process each relocation in order of offset. The relocation may however not have been
//! applied as listed. Rather, one of several relaxations might have been applied to the relocation.
//! These relaxations generally, but not always change the bytes surrounding the relocation. For
//! each relocation, we check each candidate relaxation, to see if it matches that surrounding
//! bytes. If it doesn't, we eliminate it.
//!
//! We then extract the value of the relocation by reading the bytes at the location of the
//! relocation from the output binary. This location we read from might have been adjusted by the
//! relaxation. Once we have the location, we reverse whatever transformations would have been
//! performed on it by the relocation. If, based on the relocation type, our value is an address, we
//! can then look to see what section the address points to. This allows us to eliminate further
//! relaxations by checking if the address is part of a PLT section or not.
//!
//! It might be tempting to take the address extracted from the binary and look up what is at that
//! address, however this technique leads to false matches, since multiple symbols can point to the
//! same address by coincidence. For example, a symbol that points one byte past the end of a
//! section might point to the same address as a symbol that points to the start of the next
//! section. So instead, we start from the symbol associated with the original relocation and work
//! forward, checking where it is. Provided the symbol is unique, we can then claim to have matched
//! against it.

use self::section_map::FunctionInfo;
use self::section_map::IndexedLayout;
use self::section_map::InputSectionId;
use self::section_map::SymbolInfo;
use crate::Binary;
use crate::Diff;
use crate::DiffValues;
use crate::ElfFile64;
use crate::Report;
use crate::Result;
use crate::SectionCoverage;
use crate::arch::Arch;
use crate::arch::Instruction;
use crate::arch::PltEntry;
use crate::arch::RType;
use crate::arch::Relaxation;
use crate::arch::RelaxationKind;
use crate::diagnostics::TraceOutput;
use crate::get_r_type;
use crate::section_map;
use anyhow::Context as _;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use colored::ColoredString;
use colored::Colorize as _;
use itertools::Itertools as _;
use linker_utils::elf::BitMask;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::elf::RelocationSize;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::relaxation::RelocationModifier;
use object::LittleEndian;
use object::Object as _;
use object::ObjectKind;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::RelocationTarget;
use object::SectionKind;
use object::read::elf::ElfSection64;
use object::read::elf::FileHeader as _;
use object::read::elf::ProgramHeader as _;
use object::read::elf::SectionHeader as _;
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Write as _;
use std::iter::Peekable;
use std::ops::Range;

/// Set this environment variable to a function name to show only diffs for that function.
const SHOW_FUNCTION_ENV: &str = "LINKER_DIFF_FOCUS_FUNCTION";

/// The kinds of sections that we support diffing here. Note, some other kinds of sections are
/// diffed elsewhere in linker-diff. e.g. `init_array` and `fini_array`.
const SUPPORTED_SECTION_KINDS: &[SectionKind] = &[SectionKind::Text, SectionKind::Data];

/// Reports differences in sections in particular differences in the relocations that were applied
/// to those sections, although the literal bytes between the relocations are also diffed.
pub(crate) fn report_section_diffs<A: Arch>(report: &mut Report, binaries: &[Binary]) {
    let Some(layout) = binaries[0].indexed_layout.as_ref() else {
        report.add_error("A .layout file is required");
        return;
    };

    // If we got an error building our index, then don't try to diff functions. We'd just get heaps
    // of diffs due to an incomplete index.
    if binaries
        .iter()
        .any(|o| o.address_index.index_error.is_some())
    {
        return;
    }

    if let Some(cov) = report.coverage.as_mut() {
        populate_section_coverage(cov, layout);
    }

    let by_name = symbol_versions_by_name(binaries, layout);
    let matched_sections = unified_sections_from_symbols(report, by_name, layout, binaries);

    let mut section_ids_to_process = matched_sections
        .keys()
        .copied()
        // Sort sections so that we process sections in a deterministic order, since that affects our
        // output order.
        .sorted()
        .collect_vec();

    while let Some(section_id) = section_ids_to_process.pop() {
        let section_versions = matched_sections.get(&section_id).unwrap();

        if let Err(error) = compare_sections::<A>(report, section_versions, binaries, layout) {
            report.add_diff(Diff {
                key: format!(
                    "section-diff-failed.{}",
                    section_versions
                        .original_section(layout)
                        .and_then(|s| Ok(s.name()?))
                        .unwrap_or("unknown-section")
                ),
                values: DiffValues::PreFormatted(error.to_string()),
            });
        }
    }
}

fn compare_sections<A: Arch>(
    report: &mut Report,
    section_versions: &SectionVersions<'_>,
    binaries: &[Binary],
    layout: &IndexedLayout,
) -> Result {
    let original_section = section_versions.original_section(layout)?;

    if let Some(coverage) = report.coverage.as_mut() {
        if let Some(sec_cov) = coverage
            .sections
            .get_mut(&section_versions.input_section_id)
        {
            sec_cov.diffed = true;
        }
    }

    // We already filtered input sections based on their kind. Now we filter based on the output
    // section into which the input section was placed. If we don't do this, we're likely to end up
    // diffing input sections like '.ctors' which are often just set to PROGBITS.
    if determine_output_section_kind(binaries, &section_versions.addresses_by_binary)
        .is_some_and(|output_section_kind| !SUPPORTED_SECTION_KINDS.contains(&output_section_kind))
    {
        return Ok(());
    }

    let mut testers = binaries
        .iter()
        .zip(&section_versions.addresses_by_binary)
        .map(|(bin, &section_address)| -> Result<RelaxationTester> {
            RelaxationTester::new(
                &original_section,
                bin,
                section_address,
                layout.input_file_for_section(section_versions.input_section_id),
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let section_kind = original_section.kind();

    // We need to process relocations in order since we diff the gaps between the relocations as we
    // go. We can't do that if there might be another relocation between that we just haven't seen
    // yet.
    let mut relocations = original_section.relocations().collect_vec();
    relocations.sort_by_key(|(offset, _)| *offset);

    let mut relocations = relocations.into_iter().peekable();

    while let Some(group) = RelocationGroup::<A>::next(&mut relocations, section_versions, layout)?
    {
        diff_literal_bytes::<A>(
            report,
            section_versions,
            layout,
            &mut testers,
            group
                .start_offset()
                .saturating_sub(A::MAX_RELAX_MODIFY_BEFORE),
        )?;

        // If any tester indicates that the next relocation should be skipped, then either all
        // testers will say to skip, or the previous relocation didn't match. In either case, we
        // want to skip the next relocation.
        if testers
            .iter()
            .any(|t| t.next_modifier == RelocationModifier::SkipNextRelocation)
        {
            testers
                .iter_mut()
                .for_each(|t| t.next_modifier = RelocationModifier::Normal);

            continue;
        }

        let mut resolutions = Vec::new();
        for tester in &mut testers {
            resolutions.push(tester.resolve_group_traced(section_kind, &group));
        }

        // The first resolution (the one from our linker-under-test) must be equal to at least one
        // of the other resolutions.
        if let Some(first) = resolutions.first() {
            let mut trace = TraceOutput::default();

            let at_least_one_match = crate::diagnostics::trace_scope(&mut trace, || {
                resolutions[1..].iter().any(|other| first.matches(other))
            });

            // Ideally we'd successfully match all binaries, however GNU ld when it has PLT
            // relocation for an undefined symbol emits a PLT entry that points to an invalid GOT
            // address. We don't have any good way to match something like that.
            let first_has_match_failure = first.relaxations.is_none() || first.has_error();

            if !at_least_one_match || first_has_match_failure {
                report.add_diff(resolution_diff_exec(
                    group.start_offset(),
                    group.into_original_annotations(),
                    &resolutions,
                    &testers,
                    section_versions.input_section_id,
                    layout,
                    trace,
                )?);

                update_offsets_if_match_failed(
                    section_versions,
                    layout,
                    original_section.size(),
                    &mut testers,
                    &resolutions,
                    &mut relocations,
                )?;
            }
        };
    }

    // There are no more relocations. Diff literal bytes up to the end of the section.
    diff_literal_bytes::<A>(
        report,
        section_versions,
        layout,
        &mut testers,
        original_section.size(),
    )?;

    Ok(())
}

fn determine_output_section_kind(
    binaries: &[Binary<'_>],
    addresses_by_binary: &[u64],
) -> Option<SectionKind> {
    binaries
        .iter()
        .zip(addresses_by_binary)
        .rev()
        .find_map(|(bin, address)| {
            bin.section_containing_address(*address)
                .map(|section| section.kind())
        })
}

/// If we got a match failure, then advance to the start of the next function, or if there is no
/// next function to the end of the section. This is to avoid getting follow-on errors after a match
/// failure.
fn update_offsets_if_match_failed<A: Arch>(
    section_versions: &SectionVersions<'_>,
    layout: &IndexedLayout<'_>,
    section_size: u64,
    testers: &mut Vec<RelaxationTester<'_>>,
    resolutions: &[ResolvedGroup<'_, A>],
    relocations: &mut Peekable<std::vec::IntoIter<(u64, object::Relocation)>>,
) -> Result {
    if resolutions.iter().any(|r| {
        r.annotations
            .iter()
            .any(|a| matches!(a.kind, AnnotationKind::MatchFailed(..)))
    }) {
        let offset = testers.iter().map(|t| t.previous_end).max().unwrap_or(0);

        let section_info = layout
            .get_section_info(section_versions.input_section_id)
            .context("Attempt to diff missing section")?;

        let new_offset = section_info
            .next_function_offset(offset)
            .unwrap_or(section_size);

        // Update all testers to the new location.
        testers.iter_mut().for_each(|t| t.previous_end = new_offset);

        // Skip any relocations that applied to the addresses we skipped.
        while let Some((next_rel_offset, _rel)) = relocations.peek() {
            if *next_rel_offset < new_offset {
                relocations.next();
            } else {
                break;
            }
        }
    };

    Ok(())
}

struct RelocationGroup<'data, A: Arch> {
    relocations: Vec<InputRelocation<'data, A>>,
}

#[derive(Debug, PartialEq, Eq)]
struct RelaxationGroup<'data, A: Arch> {
    /// Match results for each relocation in the group.
    match_results: Vec<RelaxationMatchResult<'data, A>>,
    is_complete: bool,
}

impl<'data, A: Arch> RelaxationGroup<'data, A> {
    fn start_offset(&self) -> u64 {
        self.match_results
            .iter()
            .map(|r| r.start())
            .min()
            .unwrap_or(0)
    }

    fn end_offset(&self) -> u64 {
        self.match_results
            .iter()
            .map(|r| r.end())
            .max()
            .unwrap_or(0)
    }

    fn first_if_matched(&self) -> Option<&RelaxationMatch<'data, A>> {
        if !self.match_results.iter().all(|m| m.matched()) {
            return None;
        }
        match self.match_results.first()? {
            RelaxationMatchResult::Matched(m) => Some(m),
            _ => None,
        }
    }

    fn eliminate_alt_r_types(&mut self, reference: &Reference<A::RType>) {
        for result in &mut self.match_results {
            if let RelaxationMatchResult::Matched(m) = result {
                if let Some(alt_r_type) = m.relaxation.alt_r_type {
                    // Some relaxations cannot be identified purely by the instruction bytes. For example
                    // relaxing a PLT32 to a PC32, the instruction bytes are left the same. All that differs is
                    // whether we now point to the PLT or not.

                    match (
                        reference.verify_consistent_with_r_type(m.relaxation.new_r_type),
                        reference.verify_consistent_with_r_type(alt_r_type),
                    ) {
                        (Err(_), Ok(())) => {
                            m.relaxation.new_r_type = alt_r_type;
                        }
                        (Ok(()), Err(_)) => {
                            m.relaxation.alt_r_type = None;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    fn matches_if_ok(&self) -> Option<Vec<RelaxationMatch<'data, A>>> {
        self.match_results
            .iter()
            .map(|r| match r {
                RelaxationMatchResult::Matched(relaxation_match) => Ok(*relaxation_match),
                _ => Err(()),
            })
            .collect::<Result<Vec<RelaxationMatch<A>>, ()>>()
            .ok()
    }

    fn matches_skipping_nops(&self) -> Vec<&RelaxationMatchResult<'data, A>> {
        self.match_results
            .iter()
            .filter(|result| !matches!(result, RelaxationMatchResult::Matched(m) if m.relaxation.relaxation_kind.is_replace_with_no_op()))
            .collect()
    }
}

impl<'data, A: Arch> RelocationGroup<'data, A> {
    fn into_original_annotations(self) -> Vec<OriginalAnnotation<'data, A>> {
        self.relocations
            .into_iter()
            .map(|r| r.original_annotation)
            .collect()
    }

    fn next(
        relocations_in: &mut Peekable<std::vec::IntoIter<(u64, object::Relocation)>>,
        section_versions: &SectionVersions<'data>,
        layout: &IndexedLayout<'data>,
    ) -> Result<Option<RelocationGroup<'data, A>>> {
        let mut relocations = Vec::new();

        let mut chain = Vec::new();

        while let Some(next_r_type) = relocations_in
            .peek()
            .map(|(_, rel)| get_r_type::<A::RType>(rel))
        {
            chain.push(next_r_type);
            if chain.len() >= 2 && !A::should_chain_relocations(&chain) {
                break;
            }

            let (offset, rel) = relocations_in.next().unwrap();

            let original_annotation =
                get_original_annotation::<A>(section_versions, layout, &rel, offset)?;

            relocations.push(InputRelocation {
                offset,
                rel,
                original_annotation,
            });
        }

        if relocations.is_empty() {
            Ok(None)
        } else {
            Ok(Some(RelocationGroup { relocations }))
        }
    }

    fn start_offset(&self) -> u64 {
        self.relocations[0].offset
    }

    fn is_complete_group(&self) -> bool {
        A::is_complete_chain(self.relocations.iter().map(|r| get_r_type(&r.rel)))
    }
}

struct InputRelocation<'data, A: Arch> {
    offset: u64,

    rel: object::Relocation,

    original_annotation: OriginalAnnotation<'data, A>,
}

impl<'data, A: Arch> InputRelocation<'data, A> {
    fn original_referent(&self) -> Referent<'data, <A as Arch>::RType> {
        self.original_annotation.reference.referent
    }
}

fn get_original_annotation<'data, A: Arch>(
    section_versions: &SectionVersions<'data>,
    layout: &IndexedLayout<'data>,
    rel: &object::Relocation,
    offset: u64,
) -> Result<OriginalAnnotation<'data, A>> {
    let mut orig_trace = TraceOutput::default();

    let original_referent = crate::diagnostics::trace_scope(&mut orig_trace, || {
        get_original_referent(
            rel,
            layout.input_file_for_section(section_versions.input_section_id),
        )
    })?;

    let original_annotation = OriginalAnnotation {
        success: MatchedRelaxation::<A> {
            r_type: get_r_type(rel),
            relaxation_kind: None,
        },
        reference: Reference {
            referent: original_referent,
            indirection: Indirection::default(),
        },
        trace: orig_trace,
        offset,
    };

    Ok(original_annotation)
}

/// Diffs literal bytes up to `end`.
fn diff_literal_bytes<'data, A: Arch>(
    report: &mut Report,
    section_versions: &SectionVersions<'data>,
    layout: &IndexedLayout<'data>,
    testers: &mut [RelaxationTester<'data>],
    end: u64,
) -> Result {
    let start = testers
        .iter()
        .map(|t| t.previous_end)
        .max()
        .unwrap_or_default();

    if end <= start {
        return Ok(());
    }

    let mut ok = true;

    for tester in testers.iter_mut() {
        // If the previous match failed, then the testers might be at different positions,
        // synchronise them.
        tester.previous_end = start;

        if end > tester.previous_end {
            ok &= tester.is_equal_up_to(end);
        }
    }

    if ok {
        // Update all the testers to the new location.
        for tester in testers {
            tester.previous_end = end;
        }
    } else {
        let resolutions = testers
            .iter()
            .map(|_| ResolvedGroup {
                relaxations: None,
                annotations: vec![Annotation {
                    offset_in_section: start,
                    kind: AnnotationKind::<A>::LiteralByteMismatch,
                }],
                reference: Reference::unknown(),
                start,
                end,
                trace: TraceOutput::default(),
            })
            .collect_vec();

        report.add_diff(resolution_diff_exec(
            end,
            vec![],
            &resolutions,
            testers,
            section_versions.input_section_id,
            layout,
            TraceOutput::default(),
        )?);
    }

    Ok(())
}

/// Represents a diff found in executable code.
struct ExecDiff<'data, A: Arch> {
    offset: u64,
    original_annotations: Vec<OriginalAnnotation<'data, A>>,
    resolutions: &'data [ResolvedGroup<'data, A>],
    testers: &'data [RelaxationTester<'data>],
    section_id: InputSectionId,
    trace: TraceOutput,
}

impl<A: Arch> ExecDiff<'_, A> {
    fn write_to(&self, f: &mut String, layout: &IndexedLayout) -> Result {
        let original_section = layout.get_elf_section(self.section_id)?;
        let file_identifier = layout.input_filename_for_section(self.section_id);

        let function_info = layout
            .get_section_info(self.section_id)
            .context("Attempted to diff a section that wasn't emitted")?
            .function_at_offset(self.offset, layout)?;

        // We'll print all instructions that overlap with this range.
        let range = self.resolutions.iter().map(|r| r.start).min().unwrap_or(0)
            ..self.resolutions.iter().map(|r| r.end).max().unwrap_or(0);

        // Print common information.
        writeln!(
            f,
            "{file_identifier} {section_name} {function_name}",
            section_name = original_section.name()?.blue(),
            function_name = String::from_utf8_lossy(function_info.name).cyan()
        )?;

        let mut trace = TraceOutput::default();

        let annotations = self
            .original_annotations
            .iter()
            .map(|orig| {
                let annotation = Annotation {
                    offset_in_section: orig.offset,
                    kind: AnnotationKind::MatchedRelaxation(orig.success.clone()),
                };

                trace.append(orig.trace.clone());

                annotation
            })
            .collect_vec();

        let mut blocks = vec![RelocationInstructionBlock {
            name: ORIG,
            annotations,
            reference: self.original_annotations.last().map(|a| a.reference),
            trace_messages: Vec::new(),
            section_bytes: original_section.data().ok(),
            section_size: original_section.size(),
            section_address: 0,
            range: range.start..range.end,
            function_info,
            instructions: Default::default(),
            trace,
        }];

        for (res, tester) in self.resolutions.iter().zip(self.testers) {
            let section_bytes = tester.section_bytes;

            let block = RelocationInstructionBlock {
                name: &tester.bin.name,
                annotations: res.annotations.clone(),
                reference: Some(res.reference),
                trace_messages: tester.bin.trace.messages_in(
                    range.start + tester.section_address..range.end + tester.section_address,
                ),
                section_bytes,
                section_size: tester.section_size,
                section_address: tester.section_address,
                range: range.start..range.end,
                function_info,
                instructions: Default::default(),
                trace: res.trace.clone(),
            };

            blocks.push(block);
        }

        if original_section.kind() == SectionKind::Text {
            for block in &mut blocks {
                let mut trace = TraceOutput::default();

                crate::diagnostics::trace_scope(&mut trace, || {
                    block.decode_instructions();
                });

                block.trace.append(trace);
            }
        }

        let maximum_widths = blocks.iter().fold(ColumnWidths::default(), |widths, b| {
            widths.merge(b.widths())
        });

        for block in &blocks {
            block.write_to(f, &maximum_widths)?;
        }

        for message in &self.trace.messages {
            write!(f, "    {message}")?;
        }

        Ok(())
    }
}

/// Produces a diff showing the different resolutions found for a relocation in some executable
/// code.
fn resolution_diff_exec<A: Arch>(
    offset: u64,
    original_annotations: Vec<OriginalAnnotation<A>>,
    resolutions: &[ResolvedGroup<A>],
    testers: &[RelaxationTester<'_>],
    section_id: InputSectionId,
    layout: &IndexedLayout,
    trace: TraceOutput,
) -> Result<Diff> {
    let bin_attributes = testers[1].bin.address_index.bin_attributes;

    let key = diff_key_for_res_mismatch(resolutions, &original_annotations, bin_attributes);

    let diff = ExecDiff {
        offset,
        original_annotations,
        resolutions,
        testers,
        section_id,
        trace,
    };

    let mut out = String::new();
    diff.write_to(&mut out, layout)?;

    Ok(Diff {
        key,
        values: DiffValues::PreFormatted(out),
    })
}

/// Returns information about what the original relocation refers to.
fn get_original_referent<'data, R: RType>(
    rel: &object::Relocation,
    input_file: &crate::section_map::InputFile<'data>,
) -> Result<Referent<'data, R>> {
    if let RelocationTarget::Symbol(symbol_index) = rel.target() {
        let symbol = input_file.elf_file.symbol_by_index(symbol_index)?;

        if let Some(section_index) = symbol.section_index() {
            let section = input_file.elf_file.section_by_index(section_index)?;

            let flags = section.elf_section_header().sh_flags(LittleEndian) as u32;

            if flags & object::elf::SHF_MERGE != 0 && flags & object::elf::SHF_STRINGS != 0 {
                let section_data = section.data()?;
                let string_plus_rest = &section_data[symbol.address() as usize..];
                if let Some(end_offset) = memchr::memchr(0, string_plus_rest) {
                    let addend = symbol
                        .name_bytes()
                        .is_ok_and(|name| !name.is_empty())
                        .then(|| rel.addend());

                    return Ok(Referent::MergedString(MergedStringRef {
                        data: &string_plus_rest[..end_offset],
                        named_symbol_addend: addend,
                    }));
                }
            }
        }

        let name_bytes = symbol.name_bytes()?;

        let name = SymbolName {
            bytes: name_bytes,
            version: None,
        };

        return Ok(Referent::Named(name, rel.addend()));
    }

    Ok(Referent::Unknown)
}

fn diff_key_for_res_mismatch<A: Arch>(
    resolutions: &[ResolvedGroup<A>],
    original_annotations: &[OriginalAnnotation<A>],
    bin_attributes: BinAttributes,
) -> String {
    if resolutions.len() < 2 {
        return "missing-resolutions".to_owned();
    }

    match (
        &resolutions[0].reference.referent,
        &resolutions[1].reference.referent,
    ) {
        (Referent::DynamicRelocation(d), Referent::Undefined(unmatched)) => {
            if d.entry.is_weak && unmatched.address == 0 {
                // The reference linker emitted a null and we emitted a dynamic
                // relocation for a weak symbol.
                return format!("rel.undefined-weak.dynamic.{}", d.r_type);
            }
        }
        (Referent::DynamicRelocation(ours), Referent::DynamicRelocation(theirs)) => {
            if !resolutions[0].reference.indirection.is_via_plt()
                && resolutions[1].reference.indirection.is_via_plt()
                && ours.addend == 0
                && theirs.addend == 0
                && ours.entry == theirs.entry
            {
                // We used an in-place relocation where the reference linker emitted the address of
                // a PLT entry for the same symbol.
                return "rel.dynamic-plt-bypass".to_owned();
            }
        }
        (Referent::Named(ours, _), Referent::Undefined(_)) => {
            // We defined a symbol that the reference linker didn't.
            return format!("rel.extra-symbol.{ours}");
        }
        (Referent::Named(_, _), Referent::DynamicRelocation(_)) => {
            if resolutions[0].reference.indirection == Indirection::Got
                && resolutions[1].reference.indirection == Indirection::Got
            {
                return format!("rel.missing-got-dynamic.{}", bin_attributes.output_kind);
            }
        }
        _ => {}
    }

    if resolutions[0]
        .reference
        .referent
        .matches(resolutions[1].reference.referent)
        && resolutions[0].reference.indirection == Indirection::Got
        && resolutions[1].reference.indirection == Indirection::GotPltGot
    {
        return "rel.missing-got-plt-got".to_owned();
    }

    // We might have failed to match one of the reference linker outputs, so find the first
    // reference linker output that we successfully matched.
    let reference = resolutions
        .iter()
        .skip(1)
        .find_map(|r| r.relaxations.as_ref().and_then(|r| r.first_if_matched()));

    let ours = resolutions[0]
        .relaxations
        .as_ref()
        .and_then(|r| r.first_if_matched());

    match (ours, reference) {
        (Some(r1), Some(r2)) => {
            let Some(orig) = original_annotations.first() else {
                return "missing-original".to_owned();
            };

            match (
                r1.relaxation.relaxation_kind.is_no_op(),
                r2.relaxation.relaxation_kind.is_no_op(),
            ) {
                (true, false) => {
                    format!(
                        "rel.missing-opt.{}.{:?}.{}",
                        orig.success.r_type,
                        r2.relaxation.relaxation_kind,
                        bin_attributes.type_name()
                    )
                }
                (false, true) => {
                    format!(
                        "rel.extra-opt.{}.{:?}.{}",
                        orig.success.r_type,
                        r1.relaxation.relaxation_kind,
                        bin_attributes.type_name()
                    )
                }
                _ => {
                    let ours_is_copy = resolutions[0].reference.referent.is_copy_relocation();
                    let any_others_copy = resolutions[1..]
                        .iter()
                        .any(|r| r.reference.referent.is_copy_relocation());

                    if ours_is_copy && !any_others_copy {
                        format!("rel.extra-copy-relocation.{}", orig.success.r_type)
                    } else if !ours_is_copy && any_others_copy {
                        format!("rel.missing-copy-relocation.{}", orig.success.r_type)
                    } else {
                        format!(
                            "rel.{}.{}",
                            r1.relaxation.new_r_type, r2.relaxation.new_r_type
                        )
                    }
                }
            }
        }
        _ => {
            let failure_kind = |r: &ResolvedGroup<A>| {
                if r.annotations
                    .iter()
                    .any(|a| matches!(a.kind, AnnotationKind::LiteralByteMismatch))
                {
                    Some("literal-byte-mismatch".to_owned())
                } else {
                    r.annotations
                        .iter()
                        .zip(original_annotations)
                        .find_map(|(a, orig)| match &a.kind {
                            AnnotationKind::Ambiguous(_) => Some("rel.multiple_matches".to_owned()),
                            AnnotationKind::MatchFailed(_) => {
                                Some(format!("rel.match_failed.{}", orig.success.r_type))
                            }
                            AnnotationKind::MatchedRelaxation(_) => None,
                            AnnotationKind::LiteralByteMismatch => {
                                unreachable!();
                            }
                            AnnotationKind::Error(e) => Some(e.clone()),
                        })
                }
            };

            failure_kind(&resolutions[0])
                .or(failure_kind(&resolutions[1]))
                .unwrap_or("rel.unknown_failure".to_owned())
        }
    }
}

/// A block of instructions containing a relocation. Only used for display purposes.
struct RelocationInstructionBlock<'data, A: Arch> {
    /// The name to display in the left-side gutter.
    name: &'data str,

    annotations: Vec<Annotation<'data, A>>,

    reference: Option<Reference<'data, A::RType>>,

    trace_messages: Vec<&'data str>,

    /// The bytes of the section.
    section_bytes: Option<&'data [u8]>,

    section_size: u64,

    /// The base address of the section. For input files, this is just zero. This only affects how
    /// addresses are rendered.
    section_address: u64,

    /// The range of bytes within the section that are of interest. All instructions that overlap
    /// with this range will be displayed. This range is based on the maximum extent of all
    /// relaxations for all the input files. It likely won't cover whole instructions.
    range: Range<u64>,

    function_info: FunctionInfo<'data>,

    /// The instructions that we're going to display.
    instructions: Vec<Instruction<'data, A>>,

    trace: TraceOutput,
}

struct OriginalAnnotation<'data, A: Arch> {
    success: MatchedRelaxation<A>,

    trace: TraceOutput,

    offset: u64,

    reference: Reference<'data, A::RType>,
}

#[derive(Clone, Debug)]
struct Annotation<'data, A: Arch> {
    /// The offset of the annotation within the section.
    offset_in_section: u64,

    kind: AnnotationKind<'data, A>,
}

#[derive(Clone, Debug)]
enum AnnotationKind<'data, A: Arch> {
    MatchedRelaxation(MatchedRelaxation<A>),
    Ambiguous(Vec<RelaxationMatch<'data, A>>),
    MatchFailed(Vec<FailedMatch<A>>),
    Error(String),
    LiteralByteMismatch,
}

#[derive(Clone, Debug)]
struct MatchedRelaxation<A: Arch> {
    r_type: A::RType,

    relaxation_kind: Option<<A as Arch>::RelaxationKind>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum RelaxationMatchResult<'data, A: Arch> {
    /// We matched to exactly one relaxation.
    Matched(RelaxationMatch<'data, A>),

    /// We failed to match all candidate relaxations. Holds the reasons why each candidate failed.
    AllFailed(Vec<FailedMatch<A>>),

    /// We matched multiple relaxations.
    Ambiguous(Vec<RelaxationMatch<'data, A>>),
}

impl<'data, A: Arch> RelaxationMatchResult<'data, A> {
    fn start(&self) -> u64 {
        match self {
            RelaxationMatchResult::Matched(relaxation_match) => relaxation_match.start,
            RelaxationMatchResult::AllFailed(failed) => {
                failed.iter().map(|m| m.start).min().unwrap_or(0)
            }
            RelaxationMatchResult::Ambiguous(matches) => {
                matches.iter().map(|m| m.start).min().unwrap_or(0)
            }
        }
    }

    fn end(&self) -> u64 {
        match self {
            RelaxationMatchResult::Matched(relaxation_match) => relaxation_match.end,
            RelaxationMatchResult::AllFailed(failed) => {
                failed.iter().map(|m| m.end).max().unwrap_or(0)
            }
            RelaxationMatchResult::Ambiguous(matches) => {
                matches.iter().map(|m| m.end).max().unwrap_or(0)
            }
        }
    }

    fn annotations(&self) -> Vec<Annotation<'data, A>> {
        match self {
            RelaxationMatchResult::Matched(relaxation_match) => {
                vec![relaxation_match.annotation()]
            }
            RelaxationMatchResult::AllFailed(failed_matches) => {
                failed_matches.iter().map(|r| r.annotation()).collect()
            }
            RelaxationMatchResult::Ambiguous(matches) => vec![Annotation {
                offset_in_section: matches.first().unwrap().offset,
                kind: AnnotationKind::Ambiguous(matches.clone()),
            }],
        }
    }

    fn matches(&self, b: &RelaxationMatchResult<'_, A>) -> bool {
        match (self, b) {
            (RelaxationMatchResult::Matched(a_match), RelaxationMatchResult::Matched(b_match)) => {
                a_match.relaxation == b_match.relaxation
            }
            _ => false,
        }
    }

    fn next_modifier(&self) -> RelocationModifier {
        match self {
            RelaxationMatchResult::Matched(m) => m.next_modifier,
            _ => RelocationModifier::Normal,
        }
    }

    fn matched(&self) -> bool {
        matches!(self, RelaxationMatchResult::Matched(_))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RelaxationMatch<'data, A: Arch> {
    relaxation: Relaxation<A>,

    /// The extracted value.
    value: u64,

    /// The inclusive start-offset of the bytes covered by this relaxation.
    start: u64,

    /// The exclusive end-offset of the bytes covered by this relaxation.
    end: u64,

    original_referent: Referent<'data, <A as Arch>::RType>,
    addend: i64,
    offset: u64,
    next_modifier: RelocationModifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FailedMatch<A: Arch> {
    candidate: Relaxation<A>,
    reason: String,
    offset: u64,
    start: u64,
    end: u64,
}

impl<A: Arch> FailedMatch<A> {
    fn new(
        candidate: Relaxation<A>,
        reason: String,
        offset: u64,
        start: u64,
        end: u64,
    ) -> FailedMatch<A> {
        FailedMatch {
            candidate,
            reason,
            offset,
            start,
            end,
        }
    }

    fn annotation(&self) -> Annotation<'static, A> {
        Annotation {
            offset_in_section: self.offset,
            kind: AnnotationKind::MatchFailed(vec![self.clone()]),
        }
    }
}

impl<A: Arch> RelocationInstructionBlock<'_, A> {
    fn widths(&self) -> ColumnWidths {
        ColumnWidths {
            name: self.name.len(),
            address: format!("{:x}", self.section_address + self.section_size).len(),
            instruction_bytes: self
                .instructions
                .iter()
                .map(|i| i.bytes.len())
                .max()
                .unwrap_or_default(),
        }
    }

    /// Decodes and stores the instructions that we're going to display.
    fn decode_instructions(&mut self) {
        let Some(section_bytes) = self.section_bytes else {
            return;
        };

        self.instructions = A::decode_instructions_in_range(
            section_bytes,
            self.section_address,
            self.function_info.offset_in_section,
            self.range.clone(),
        );
    }

    fn write_to(&self, f: &mut String, maximum_widths: &ColumnWidths) -> Result {
        let name_width = maximum_widths.name;
        let address_width = maximum_widths.address;

        let mut annotations = self.annotations.iter().peekable();

        for instruction in &self.instructions {
            let instruction_offset = instruction.address() - self.section_address;

            let instruction_end = instruction_offset + instruction.bytes.len() as u64;

            write!(
                f,
                "{:name_width$} 0x{:0address_width$x}: [ ",
                self.name.blue(),
                instruction.address()
            )?;

            // Print instruction bytes.
            let mut offset = instruction.address() - self.section_address;
            for v in instruction.bytes {
                if self.range.contains(&offset) {
                    // Bytes within the range that we would have compared are highlighted yellow,
                    // while bytes outside the range are left in the default colour. This makes it
                    // easier to spot what's going on if our ranges are wrong.
                    write!(f, "{} ", format!("{v:02x}").yellow())?;
                } else {
                    write!(f, "{v:02x} ")?;
                }
                offset += 1;
            }

            let out = A::instruction_to_string(instruction);

            let instruction_padding =
                (maximum_widths.instruction_bytes - instruction.bytes.len()) * 3;

            writeln!(f, "{:instruction_padding$}] {}", "", out.purple())?;

            if let Some(annotation) = annotations.peek() {
                if annotation.offset_in_section >= instruction_offset
                    && annotation.offset_in_section < instruction_end
                {
                    let num_spaces = name_width
                        + address_width
                        + 7
                        + (annotation.offset_in_section - instruction_offset) as usize * 3;

                    annotation.write(f, &format!("{:num_spaces$}", ""))?;

                    annotations.next();
                }
            }
        }

        if self.instructions.is_empty() {
            write!(
                f,
                "{name:name_width$} 0x{address:0address_width$x}: [ ",
                name = self.name.blue(),
                address = self.section_address + self.range.start,
            )?;

            for i in self.range.clone() {
                let byte = self
                    .section_bytes
                    .and_then(|bytes| bytes.get(i as usize).copied())
                    .unwrap_or(0);

                write!(f, "{} ", format!("{byte:02x}").yellow())?;
            }
            writeln!(f, "]")?;
        }

        // Print any remaining annotations.
        for annotation in annotations {
            let num_spaces = name_width + address_width + 6;
            annotation.write(f, &format!("{:num_spaces$} ", self.name.blue()))?;
        }

        if let Some(r) = self.reference {
            write!(f, "{:name_width$} ", self.name.blue())?;
            r.write_to(f)?;
        }

        writeln!(f)?;

        self.write_traces(f, maximum_widths)?;

        for message in &self.trace.messages {
            writeln!(f, "{:name_width$} {message}", self.name.blue())?;
        }

        Ok(())
    }

    fn write_traces(&self, f: &mut String, maximum_widths: &ColumnWidths) -> Result {
        let name_width = maximum_widths.name;
        let prefix = " TRACE: ";

        for trace in &self.trace_messages {
            writeln!(f, "{:name_width$}{prefix}{trace}", self.name.blue())?;
        }

        Ok(())
    }
}

impl<A: Arch> Annotation<'_, A> {
    fn write(&self, f: &mut String, line_prefix: &str) -> Result {
        match &self.kind {
            AnnotationKind::MatchedRelaxation(inner) => {
                inner.write_to(f, line_prefix)?;
                writeln!(f)?;
            }
            AnnotationKind::Ambiguous(possible) => {
                for a in possible {
                    a.write_to(f, line_prefix)?;
                    writeln!(f)?;
                }
            }
            AnnotationKind::MatchFailed(failures) => {
                for m in failures {
                    write!(f, "{line_prefix}")?;
                    m.write_to(f)?;
                    writeln!(f)?;
                }
            }
            AnnotationKind::Error(error) => {
                writeln!(f, "{line_prefix}{}", error.red())?;
            }
            AnnotationKind::LiteralByteMismatch => {
                return Ok(());
            }
        }

        Ok(())
    }
}

impl<A: Arch> MatchedRelaxation<A> {
    fn write_to(&self, f: &mut String, line_prefix: &str) -> Result {
        write!(f, "{line_prefix}")?;
        write_carets_for_r_type(f, self.r_type)?;
        write!(f, "{} ", self.r_type.to_string().green())?;
        if let Some(r) = self.relaxation_kind {
            write!(f, "{} ", format!("{r:?}").bright_green())?;
        }

        Ok(())
    }
}

impl<'data, A: Arch> RelaxationMatch<'data, A> {
    fn write_to(&self, f: &mut String, line_prefix: &str) -> Result {
        let rel = self.relaxation;

        write!(f, "{line_prefix}")?;
        write_carets_for_r_type(f, rel.new_r_type)?;

        write!(f, "{} ", rel.new_r_type.to_string().green())?;

        if let Some(alt) = rel.alt_r_type {
            write!(f, "/{} ", alt.to_string().green())?;
        }

        writeln!(
            f,
            "{} ",
            format!("{:?}", rel.relaxation_kind).bright_green()
        )?;

        Ok(())
    }

    fn annotation(&self) -> Annotation<'data, A> {
        Annotation {
            offset_in_section: self.offset,
            kind: AnnotationKind::MatchedRelaxation(MatchedRelaxation {
                r_type: self.relaxation.new_r_type,
                relaxation_kind: Some(self.relaxation.relaxation_kind),
            }),
        }
    }
}

fn write_carets_for_r_type<R: RType>(f: &mut String, r_type: R) -> Result {
    let num_carets = num_carets_for_r_type(r_type);
    write!(f, "{:^<num_carets$} ", "")?;
    Ok(())
}

fn num_carets_for_r_type<R: RType>(r_type: R) -> usize {
    let relocation_size = r_type.opt_relocation_info().map_or(1, relocation_num_bytes);
    (relocation_size * 3).saturating_sub(1).max(1)
}

impl<A: Arch> FailedMatch<A> {
    fn write_to(&self, f: &mut String) -> Result {
        write_carets_for_r_type(f, self.candidate.new_r_type)?;

        write!(
            f,
            "{} {:?} {}",
            self.candidate.new_r_type.to_string().green(),
            self.candidate.relaxation_kind,
            self.reason.red()
        )?;
        Ok(())
    }
}

/// The widths of columns so that we can align stuff.
#[derive(Default, PartialEq, Eq, Clone, Copy)]
struct ColumnWidths {
    name: usize,
    address: usize,
    instruction_bytes: usize,
}

impl ColumnWidths {
    fn merge(&self, other: ColumnWidths) -> ColumnWidths {
        ColumnWidths {
            name: self.name.max(other.name),
            address: self.address.max(other.address),
            instruction_bytes: self.instruction_bytes.max(other.instruction_bytes),
        }
    }
}

#[derive(Debug)]
struct ResolvedGroup<'data, A: Arch> {
    /// The chosen relaxation if we successfully matched to exactly one.
    relaxations: Option<RelaxationGroup<'data, A>>,

    annotations: Vec<Annotation<'data, A>>,

    reference: Reference<'data, A::RType>,

    /// The inclusive start of the bytes associated with this resolution.
    start: u64,

    /// The exclusive end of the bytes associated with this resolution. This should the the offset
    /// of the first byte after the later of (a) any instructions modified by the relaxation and (b)
    /// the bytes of the relocation offset.
    end: u64,

    trace: TraceOutput,
}

impl<A: Arch> ResolvedGroup<'_, A> {
    /// Returns whether two resolutions from different objects files match. Like equality, but only
    /// looks at the parts of the resolution that are expected to match.
    fn matches(&self, other: &ResolvedGroup<A>) -> bool {
        relaxations_match(self.relaxations.as_ref(), other.relaxations.as_ref())
            && self.reference.matches(other.reference)
    }

    fn has_error(&self) -> bool {
        self.annotations
            .iter()
            .any(|a| matches!(a.kind, AnnotationKind::Error(_)))
    }
}

fn relaxations_match<A: Arch>(
    group1: Option<&RelaxationGroup<'_, A>>,
    group2: Option<&RelaxationGroup<'_, A>>,
) -> bool {
    match (group1, group2) {
        (None, None) => true,
        (Some(_), None) => false,
        (None, Some(_)) => false,
        (Some(a), Some(b)) => {
            // Ignore replace with NOP relaxations.
            let a_match_results = a.matches_skipping_nops();
            let b_match_results = b.matches_skipping_nops();

            if a_match_results.len() != b_match_results.len() {
                return false;
            }

            a_match_results
                .iter()
                .zip(&b_match_results)
                .all(|(a, b)| a.matches(b))
        }
    }
}

/// Information about a thing that we reference and how it was referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reference<'data, R: RType> {
    referent: Referent<'data, R>,

    /// How we got to the referent.
    indirection: Indirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Indirection {
    #[default]
    Direct,
    Got,
    PltGot,
    GotPltGot,
}

impl Indirection {
    fn is_via_plt(self) -> bool {
        matches!(self, Indirection::PltGot)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Referent<'data, R: RType> {
    Unknown,

    /// We have a name for the thing we reference. Second value is an offset from that name in case
    /// we're not pointing directly to it.
    Named(SymbolName<'data>, i64),

    /// Like `Named`, but where the symbol has been copy relocated.
    Copy(SymbolName<'data>, i64),

    DynamicRelocation(DynamicRelocation<'data, R>),

    UnmatchedAddress(UnmatchedAddress),
    UnmatchedTlsOffset(i64),

    /// Like `UnmatchedAddress` but where the original referent is not defined in our output file,
    /// either because it really is undefined, or because it's a local like `.Ldata1` that is
    /// generally not included in the symbol table.
    Undefined(UnmatchedAddress),

    Absolute(u64),

    MergedString(MergedStringRef<'data>),

    /// A reference to an ifunc.
    IFunc(Option<SymbolName<'data>>),

    TlsGd(SymtabEntryInfo<'data>),
    TlsModuleId,
    TlsDescCall,
    TlsDesc(SymtabEntryInfo<'data>),

    /// No relocation is applied. This is used for example when a TLSLD relocation is optimised
    /// away.
    NoRelocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MergedStringRef<'data> {
    data: &'data [u8],

    /// An addend applied to the string after determining which string we're working with. Only
    /// present when our string reference is via a named symbol. For unnamed symbols (section
    /// references), the addend is assumed to be applied before determining which string we're
    /// referencing.
    named_symbol_addend: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct UnmatchedAddress {
    address: u64,
    reason: &'static str,
}

impl<'data, R: RType> Reference<'data, R> {
    fn write_to(&self, f: &mut String) -> Result {
        match self.indirection {
            Indirection::Direct => {}
            Indirection::Got => write!(f, "GOT{}", arrow())?,
            Indirection::PltGot => write!(f, "PLT{}GOT{}", arrow(), arrow())?,
            Indirection::GotPltGot => write!(f, "GOT{}PLT{}GOT{}", arrow(), arrow(), arrow())?,
        }

        self.referent.write_to(f)?;

        Ok(())
    }

    fn matches(self, other: Reference<'_, R>) -> bool {
        self.indirection == other.indirection && self.referent.matches(other.referent)
    }

    fn verify_consistent_with_r_type(&self, new_r_type: R) -> Result<()> {
        let rel_info = new_r_type.relocation_info()?;

        match rel_info.kind {
            RelocationKind::PltRelative | RelocationKind::PltRelGotBase => {
                if !self.indirection.is_via_plt() {
                    bail!("PLT relocation with non-PLT address");
                }
            }
            _ => {
                if self.indirection.is_via_plt() {
                    bail!("Non-PLT relocation with PLT address");
                }
            }
        }

        Ok(())
    }

    fn unknown() -> Reference<'data, R> {
        Reference {
            referent: Referent::Unknown,
            indirection: Default::default(),
        }
    }
}

impl<R: RType> Referent<'_, R> {
    fn write_to(&self, f: &mut String) -> Result {
        match self {
            Referent::Unknown => write!(f, "??")?,
            Referent::Named(symbol_name, offset) => {
                write!(f, "{symbol_name}")?;

                if *offset != 0 {
                    write!(f, " {offset:+}")?;
                }
            }
            Referent::Copy(symbol_name, offset) => {
                write!(f, "COPY({symbol_name}")?;

                if *offset != 0 {
                    write!(f, " {offset:+}")?;
                }

                write!(f, ")")?;
            }
            Referent::UnmatchedAddress(unmatched) | Referent::Undefined(unmatched) => {
                unmatched.write_to(f)?;
            }
            Referent::UnmatchedTlsOffset(offset) => {
                write!(f, "UnmatchedTlsOffset({offset})")?;
            }
            Referent::Absolute(value) => {
                write!(f, "#0x{value:x}")?;
            }
            Referent::MergedString(merged) => {
                merged.write_to(f)?;
            }
            Referent::DynamicRelocation(dynamic_relocation) => dynamic_relocation.write_to(f)?,
            Referent::TlsDesc(symbol) => write!(f, "TlsDesc({symbol})")?,
            Referent::IFunc(Some(symbol)) => write!(f, "IFunc({symbol})")?,
            Referent::IFunc(None) => write!(f, "UnknownIFunc")?,
            Referent::TlsModuleId => write!(f, "TlsModuleId")?,
            Referent::TlsGd(symbol) => write!(f, "TlsGd({symbol})")?,
            Referent::TlsDescCall => write!(f, "TlsDescCall")?,
            Referent::NoRelocation => write!(f, "NoRelocation")?,
        }

        Ok(())
    }

    fn matches(self, other: Referent<'_, R>) -> bool {
        match (self, other) {
            (Referent::Undefined(_), Referent::Undefined(_)) => {
                // We don't yet support matching things that don't have symbol names. So long as
                // both files don't have a name for something, we accept it.
                true
            }
            (Referent::DynamicRelocation(a), Referent::DynamicRelocation(b)) => a.matches(b),
            _ => self == other,
        }
    }

    fn is_copy_relocation(&self) -> bool {
        matches!(self, Referent::Copy(..))
    }
}

impl MergedStringRef<'_> {
    fn write_to(&self, f: &mut String) -> Result {
        if let Ok(str) = core::str::from_utf8(self.data) {
            write!(f, "MergedString({str:?})")?;
        } else {
            write!(f, "MergedString(InvalidUtf8({:?}))", self.data)?;
        }

        if let Some(addend) = self.named_symbol_addend {
            write!(f, "{addend:+}")?;
        }

        Ok(())
    }
}

impl UnmatchedAddress {
    fn write_to(&self, f: &mut String) -> Result {
        write!(f, "0x{:x} ({})", self.address, self.reason)?;

        Ok(())
    }
}

impl<R: RType> DynamicRelocation<'_, R> {
    fn matches(self, other: DynamicRelocation<'_, R>) -> bool {
        self.normalised() == other.normalised()
    }

    fn normalised(self) -> Self {
        let mut out = self;

        // Other linkers appear to emit jump slot relocations even when `-z now` is passed, whereas
        // we emit GLOB_DAT relocations. So we normalise to GLOB_DAT so as to treat them as
        // equivalent.
        if self.r_type.dynamic_relocation_kind() == Some(DynamicRelocationKind::JumpSlot) {
            out.r_type = R::from_dynamic_relocation_kind(DynamicRelocationKind::GotEntry);
        }

        // TODO: Remove this. We currently don't propagate symbol visibility correctly when emitting
        // dynamic symbols.
        out.entry.is_weak = false;

        out
    }
}

impl<R: RType> DynamicRelocation<'_, R> {
    fn write_to(&self, f: &mut String) -> Result {
        write!(
            f,
            "{}{}{}",
            self.r_type.to_string().green().bold(),
            arrow(),
            self.entry.to_string().cyan()
        )?;
        if self.addend != 0 {
            write!(f, " {:+}", self.addend)?;
        }
        Ok(())
    }
}

fn arrow() -> ColoredString {
    "->".bright_yellow()
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum BasicValueKind {
    /// The value is a pointer. We can do things like check to see if it's pointing to a PLT or
    /// GOT entry. If we tried to do that with things that weren't pointers, then we might get
    /// false PLT/GOT matches.
    Pointer,

    AbsoluteValue,

    TlsOffset,

    Aarch64TlsOffset,

    TlsGd,

    TlsModuleId,

    TlsDesc,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum ValueKind {
    Unwrapped(BasicValueKind),
    Got(BasicValueKind),
    OptionalPlt,
}

#[derive(Clone)]
struct RelaxationTester<'data> {
    /// The section data from the original input object.
    original_data: &'data [u8],

    section_address: u64,

    section_bytes: Option<&'data [u8]>,

    section_size: u64,

    /// The exclusive offset of the end of the previous resolution. Bytes from this offset should be
    /// checked when considering the next resolution.
    previous_end: u64,

    /// Indicates whether the next relocation should be skipped. This is used when a relaxation
    /// replaces not only the current relocation, but the next one too. For example when relaxing
    /// TLSGD to initial exec, the second relocation is a call to `__tls_get_addr` that is no longer
    /// needed.
    next_modifier: RelocationModifier,

    bin: &'data Binary<'data>,
}

impl<'data> RelaxationTester<'data> {
    fn new(
        original_section: &ElfSection64<'data, '_, LittleEndian>,
        bin: &'data Binary<'data>,
        section_address: u64,
        input_file: &section_map::InputFile,
    ) -> Result<Self> {
        let section_len = original_section.size();
        let section_kind = original_section.kind();

        let section_bytes;

        match section_kind {
            SectionKind::UninitializedData | SectionKind::UninitializedTls | SectionKind::Tls => {
                section_bytes = None;
            }
            _ => {
                section_bytes = read_bytes(bin.elf_file, section_address, section_len)?;

                if section_bytes.is_none() {
                    bail!(
                        "Couldn't read {section_len} bytes for section `{section}` \
                            from {input_file} at address 0x{section_address:x} \
                            in `{output_path}`",
                        output_path = bin.path.display(),
                        section = original_section.name()?,
                    );
                }
            }
        }

        Ok(RelaxationTester {
            original_data: original_section.data()?,
            section_bytes,
            section_size: original_section.size(),
            previous_end: 0,
            next_modifier: RelocationModifier::Normal,
            bin,
            section_address,
        })
    }

    /// Checks if the bytes in `section_data` match what we'd expect if the candidate relocation
    /// were applied to `original_data`. If it does, returns the value of the symbol used when the
    /// post-relaxation relocation was applied.
    fn match_relaxation<A: Arch>(
        &self,
        candidate: Relaxation<A>,
        rel: &InputRelocation<'data, A>,
    ) -> Result<RelaxationMatch<'data, A>, FailedMatch<A>> {
        let mut offset = rel.offset;
        let relaxation_range = A::relaxation_byte_range(candidate);

        let base_scratch_offset = relaxation_range.offset_shift;
        let copy_start = offset.saturating_sub(base_scratch_offset) as usize;
        let copy_end = copy_start + relaxation_range.num_bytes;
        let end =
            (offset + candidate.relocation_num_bytes().unwrap_or(0) as u64).max(copy_end as u64);

        let failure = move |reason: String| {
            Err(FailedMatch::new(
                candidate,
                reason,
                offset,
                copy_start as u64,
                end,
            ))
        };

        // Relocations need to have been previously sorted by offset.
        if offset < self.previous_end {
            return failure(format!(
                "Relocations out of order or overlap {offset} < {}",
                self.previous_end
            ));
        }

        if offset < relaxation_range.offset_shift {
            // There aren't enough bytes prior to offset in this section for the relaxation to be
            // possible.
            return failure("Not enough bytes prior".into());
        }

        // If our output section has no data (e.g. BSS), then no relaxation can have been applied,
        // since there would be no place to write the byte changes. Also, BSS isn't executable.
        let Some(section_data) = self.section_bytes else {
            return failure("Attempted to diff section without data".into());
        };

        let mut scratch =
            vec![0_u8; (A::MAX_RELAX_MODIFY_BEFORE + A::MAX_RELAX_MODIFY_AFTER) as usize];

        if copy_end > self.original_data.len() {
            return failure("Not enough bytes after".into());
        }

        let copy_len = copy_end - copy_start;
        let scratch = &mut scratch[..copy_len];

        // Copy part of the original input section into our scratch buffer so that we can apply the
        // relaxation to it and see if it matches what's in the output section.
        scratch.copy_from_slice(&self.original_data[copy_start..copy_end]);

        let previous_end = self.previous_end as usize;
        if section_data[previous_end..copy_start] != self.original_data[previous_end..copy_start] {
            // The bytes between the end of the last relocation and the start of the candidate
            // relaxation don't match.
            return Err(FailedMatch::new(
                candidate,
                format!(
                    "Prior bytes didn't match [0x{:x}..0x{:x})",
                    self.section_address + previous_end as u64,
                    self.section_address + copy_start as u64,
                ),
                offset,
                previous_end as u64,
                end,
            ));
        }

        let mut addend = rel.rel.addend();

        // Apply the relaxation to our scratch buffer.
        let mut scratch_offset = base_scratch_offset;
        let next_modifier = A::next_relocation_modifier(candidate.relaxation_kind);
        A::apply_relaxation(
            candidate.relaxation_kind,
            scratch,
            &mut scratch_offset,
            &mut addend,
        );

        let mask = A::relaxation_mask(candidate, scratch_offset as usize);

        // Check to see if the resulting bytes match what's in the output section.
        if !mask.matches(scratch, &section_data[copy_start..copy_end]) {
            return failure(format!(
                "Relaxation output didn't match: {:x?} != {:x?}",
                mask.mask_value(scratch),
                mask.mask_value(&section_data[copy_start..copy_end])
            ));
        }

        // Based on the change in offset when we applied the relaxation, compute the relocation
        // offset.
        offset = copy_start as u64 + scratch_offset;

        let Some(value_bytes) = section_data.get(offset as usize..) else {
            return failure("Invalid relocation offset".into());
        };

        let value = match candidate
            .relocation_size()
            .and_then(|size| read_value(size, value_bytes))
        {
            Ok(v) => v,
            Err(error) => return failure(error.to_string()),
        };

        Ok(RelaxationMatch {
            relaxation: candidate,
            value,
            start: copy_start as u64,
            end,
            original_referent: rel.original_referent(),
            addend,
            offset,
            next_modifier,
        })
    }

    fn read_reference<A: Arch>(
        &self,
        relaxations_matches: &[RelaxationMatch<A>],
    ) -> Result<Reference<'data, A::RType>> {
        let mut merged_value: u64 = 0;
        let mut addend = 0;
        let mut referent = None;

        // Whether all relocations have been optimised away.
        let mut all_none = true;

        let mut value_kind = ValueKind::OptionalPlt;

        // Empty groups are not permitted.
        let last_match = relaxations_matches.last().unwrap();

        for relaxation_match in relaxations_matches {
            // If we get any runtime relocation, then use that. We should generally only see these
            // in data sections (provided text relocations are disabled).
            if let Some(runtime_relocation) = self
                .bin
                .address_index
                .relocation_at_address(self.section_address + relaxation_match.start)
            {
                let r_type = get_r_type(runtime_relocation);

                if let Some(symbol) = self.symtab_entry_for_relocation(runtime_relocation) {
                    return Ok(Reference {
                        referent: Referent::DynamicRelocation(DynamicRelocation {
                            entry: *symbol,
                            r_type,
                            addend: runtime_relocation.addend(),
                        }),
                        indirection: Indirection::Direct,
                    });
                }

                match r_type.dynamic_relocation_kind() {
                    Some(DynamicRelocationKind::Relative) => {
                        merged_value =
                            merged_value.wrapping_add(runtime_relocation.addend() as u64);
                        continue;
                    }
                    Some(DynamicRelocationKind::Irelative) => {
                        return Ok(Reference {
                            referent: Referent::IFunc(determine_ifunc_name(
                                runtime_relocation.addend() as u64,
                                self.bin,
                            )),
                            indirection: Indirection::Direct,
                        });
                    }
                    _ => {
                        bail!("Unhandled dynamic relocation {r_type}");
                    }
                }
            }

            let mut value = relaxation_match.value;

            if relaxation_match
                .relaxation
                .new_r_type
                .should_ignore_when_computing_referent()
            {
                value = 0;
            }

            // We keep the addend separate from the value because we need to handle merged-strings
            // before we apply the addend.
            addend = relaxation_match.addend;

            let offset = relaxation_match.offset;

            let relocation_info = relaxation_match.relaxation.new_r_type.relocation_info()?;

            let relative_to = self.get_relative_to::<A>(offset, relocation_info)?;

            if let Some(kind) =
                value_kind_for_relocation::<A>(relocation_info.kind, &self.bin.address_index)
            {
                value_kind = kind;
            }

            if relocation_info.kind != RelocationKind::None {
                all_none = false;
            }

            match relocation_info.kind {
                RelocationKind::TlsDescCall => {
                    referent = Some(Referent::TlsDescCall);
                }
                _ => {}
            }

            if relative_to != 0 && relocation_num_bytes(relocation_info) == 4 {
                // Our value is actually an i32. Sign-extend it so that negative values behave
                // correctly in the wrapping_add below.
                value = i64::from(value as i32) as u64;
            }

            value = relative_to.wrapping_add(value);

            merged_value = merged_value.wrapping_add(value);
        }

        if all_none {
            referent = Some(Referent::NoRelocation);
        }

        // The relocation info for our primary and alt r-types should be the same for our purposes
        // here.
        let last_relocation_info = last_match.relaxation.new_r_type.relocation_info()?;

        let mut indirection = Indirection::Direct;

        loop {
            match value_kind {
                ValueKind::OptionalPlt => {
                    let pointer = merged_value.wrapping_sub(addend as u64);

                    let got_address = self.bin.address_index.plt_to_got_address::<A>(pointer)?;

                    let Some(got_address) = got_address else {
                        value_kind = ValueKind::Unwrapped(BasicValueKind::Pointer);
                        continue;
                    };

                    if indirection == Indirection::Got {
                        indirection = Indirection::GotPltGot;
                    } else {
                        indirection = Indirection::PltGot;
                    }

                    if !self.bin.address_index.is_got_address(got_address) {
                        bail!(
                            "PLT entry at 0x{pointer:x} points to non-GOT address 0x{got_address:x} in {}",
                            self.bin
                                .section_name_containing_address(got_address)
                                .unwrap_or("??")
                        );
                    }

                    merged_value = got_address;
                    addend = 0;
                    value_kind = ValueKind::Got(BasicValueKind::Pointer);
                }
                ValueKind::Got(inner_kind) => {
                    merged_value = merged_value.wrapping_sub(addend as u64);
                    addend = 0;

                    if !self.bin.address_index.is_got_address(merged_value) {
                        bail!("Expected GOT address, got 0x{merged_value:x}");
                    }

                    if indirection == Indirection::Direct {
                        indirection = Indirection::Got;
                    }

                    let got_entry = self.bin.address_index.dereference_got_address(
                        merged_value,
                        last_relocation_info.kind,
                        self.bin,
                        inner_kind,
                    )?;

                    match got_entry {
                        Referent::UnmatchedAddress(unmatched) => merged_value = unmatched.address,
                        Referent::Absolute(absolute_value)
                            if !self.bin.address_index.is_relocatable() =>
                        {
                            // Our binary is non-relocatable, so we can treat an absolute value like
                            // an address.
                            merged_value = absolute_value;
                        }
                        Referent::UnmatchedTlsOffset(offset) => {
                            merged_value = offset as u64;
                        }
                        other => {
                            referent = Some(other);
                        }
                    }

                    value_kind = ValueKind::Unwrapped(inner_kind);
                }
                ValueKind::Unwrapped(_) => break,
            }
        }

        // We need to handle merged strings after GOT pointers are dereferenced, since it's possible
        // to reference a merged string via the GOT. We also need to handle merged strings before
        // the addend is added, since how we handle the addend with merged strings depends on
        // whether the reference is via a named symbol or not.
        if let Referent::MergedString(orig_merged) = last_match.original_referent {
            referent = Some(self.resolve_merged_string::<A>(
                merged_value,
                last_relocation_info,
                orig_merged,
            )?);
        }

        merged_value = merged_value.wrapping_sub(addend as u64);

        let referent = referent.unwrap_or_else(|| {
            self.resolve_by_symbol_name::<A>(merged_value, last_match.original_referent, value_kind)
        });

        Ok(Reference {
            referent,
            indirection,
        })
    }

    /// Attempts to confirm that `merged_value` is a reference to `original_referent`, or if it
    /// isn't, tells us why.
    fn resolve_by_symbol_name<A: Arch>(
        &self,
        mut merged_value: u64,
        original_referent: Referent<'_, <A as Arch>::RType>,
        expected_value_kind: ValueKind,
    ) -> Referent<'data, <A as Arch>::RType> {
        let reason;

        if let Referent::Named(original_name, original_addend) = original_referent {
            let lookup_result = self.bin.symbol_by_name(original_name.bytes, merged_value);

            match &lookup_result {
                crate::NameLookupResult::Defined(elf_symbol) => {
                    let expected_value = match expected_value_kind {
                        ValueKind::Unwrapped(BasicValueKind::TlsOffset) => {
                            match self.bin.address_index.bin_attributes.output_kind {
                                OutputKind::Executable => {
                                    // The value will have been extracted from a u32, but since it's
                                    // expected to be negative, we need to sign-extend it.
                                    merged_value = i64::from(merged_value as i32) as u64;

                                    // In executable TLS offsets are negative values that are
                                    // relative to the TCB (thread control block), which is
                                    // immediately after the TLS segment, possibly with padding to
                                    // align it to the platforms pointer size.
                                    elf_symbol.address().wrapping_sub(
                                        self.bin
                                            .address_index
                                            .tls_segment_size
                                            .next_multiple_of(size_of::<u64>() as u64),
                                    )
                                }
                                OutputKind::SharedObject => elf_symbol.address(),
                            }
                        }
                        ValueKind::Unwrapped(BasicValueKind::Aarch64TlsOffset) => {
                            // Two words are reserved at the start of the TLS segment for the
                            // runtime.
                            elf_symbol.address() + 2 * 8
                        }
                        _ => elf_symbol.address(),
                    };

                    let offset = merged_value.wrapping_sub(expected_value) as i64;

                    if let Ok(mut bytes) = elf_symbol.name_bytes() {
                        // Strip versions from symbol names, since there are currently
                        // differences between the linkers in terms of whether version names are
                        // added to debug symbols or not. TODO: Look at changing this.
                        if let Some(at_index) = memchr::memchr(b'@', bytes) {
                            bytes = &bytes[..at_index];
                        }

                        if bytes.is_empty() {
                            reason = "Symbol has empty name";
                        } else {
                            let symbol_name = SymbolName {
                                bytes,
                                version: None,
                            };

                            if offset.abs() <= 8 + original_addend.abs() {
                                if has_copy_relocation_for_symbol_named::<A::RType>(
                                    original_name.bytes,
                                    self.bin,
                                ) {
                                    return Referent::Copy(symbol_name, offset);
                                }
                                return Referent::Named(symbol_name, offset);
                            }

                            reason = "symbol is too far away";
                        }
                    } else {
                        reason = "Error reading symbol name";
                    }
                }
                crate::NameLookupResult::Undefined => {
                    reason = "symbol is undefined";
                }
                crate::NameLookupResult::Duplicate => {
                    reason = "symbol has multiple definitions";
                }
            }

            if original_name.bytes.starts_with(b".L")
                || original_name.bytes.is_empty()
                || matches!(lookup_result, crate::NameLookupResult::Undefined)
            {
                return Referent::Undefined(UnmatchedAddress {
                    address: merged_value,
                    reason,
                });
            }
        } else {
            reason = "original symbol has no name";
        }

        Referent::UnmatchedAddress(UnmatchedAddress {
            address: merged_value,
            reason,
        })
    }

    fn resolve_merged_string<A: Arch>(
        &self,
        merged_value: u64,
        last_relocation_info: RelocationKindInfo,
        orig_merged: MergedStringRef<'_>,
    ) -> Result<Referent<'data, <A as Arch>::RType>> {
        let string_address = if let Some(named_symbol_addend) = orig_merged.named_symbol_addend {
            (merged_value as i64 - named_symbol_addend) as u64
        } else if last_relocation_info.kind == RelocationKind::Relative {
            merged_value + A::relocation_to_pc_offset(&last_relocation_info)
        } else {
            merged_value
        };

        let bytes = read_bytes_starting_at(self.bin.elf_file, string_address)
            .ok()
            .flatten()
            .with_context(|| format!("Failed to read bytes starting at 0x{string_address:x}"))?;
        let null_offset = memchr::memchr(0, bytes).with_context(|| {
            format!("Missing null-terminator for merged string starting at 0x{string_address:x}")
        })?;

        Ok(Referent::MergedString(MergedStringRef {
            data: &bytes[..null_offset],
            named_symbol_addend: None,
        }))
    }

    /// Returns the value that a relocation is relative to.
    fn get_relative_to<A: Arch>(
        &self,
        offset: u64,
        relocation_info: RelocationKindInfo,
    ) -> Result<u64> {
        let mut relative_to = match relocation_info.kind {
            RelocationKind::Relative
            | RelocationKind::RelativeRiscVLow12
            | RelocationKind::PltRelative
            | RelocationKind::TlsGd
            | RelocationKind::TlsLd
            | RelocationKind::TlsDesc
            | RelocationKind::GotTpOff
            | RelocationKind::GotRelative => self.section_address + offset,
            RelocationKind::SymRelGotBase
            | RelocationKind::GotRelGotBase
            | RelocationKind::TlsGdGotBase
            | RelocationKind::GotTpOffGotBase
            | RelocationKind::TlsLdGotBase
            | RelocationKind::TlsDescGotBase
            | RelocationKind::PltRelGotBase => self
                .bin
                .address_index
                .got_base_address
                .context("Missing GOT base address")?,
            RelocationKind::Absolute
            | RelocationKind::AbsoluteSet
            | RelocationKind::AbsoluteSetWord6
            | RelocationKind::AbsoluteAddition
            | RelocationKind::AbsoluteSubtraction
            | RelocationKind::AbsoluteSubtractionWord6
            | RelocationKind::Got
            | RelocationKind::TlsGdGot
            | RelocationKind::GotTpOffGot
            | RelocationKind::AbsoluteAArch64
            | RelocationKind::TlsDescGot
            | RelocationKind::TlsLdGot
            | RelocationKind::DtpOff
            | RelocationKind::TpOff
            | RelocationKind::TlsDescCall
            | RelocationKind::PairSubtraction
            | RelocationKind::None
            | RelocationKind::Alignment => 0,
        };

        relative_to &= A::get_relocation_base_mask(&relocation_info);

        Ok(relative_to)
    }

    fn resolve_group_traced<A: Arch>(
        &mut self,
        section_kind: SectionKind,
        group: &RelocationGroup<'data, A>,
    ) -> ResolvedGroup<'data, A> {
        let mut trace = TraceOutput::default();

        let mut res = crate::diagnostics::trace_scope(&mut trace, || {
            let relaxation_group = self.determine_relaxations(section_kind, group);
            self.resolve_group(relaxation_group)
        });

        res.trace = trace;

        res
    }

    fn determine_relaxations<A: Arch>(
        &mut self,
        section_kind: SectionKind,
        group: &RelocationGroup<'data, A>,
    ) -> RelaxationGroup<'data, A> {
        let match_results = group
            .relocations
            .iter()
            .map(|rel| {
                let r_type = get_r_type(&rel.rel);

                let mut matched_relaxations = Vec::new();
                let mut failed_matches = Vec::new();

                A::possible_relaxations_do(r_type, section_kind, |relaxation| {
                    match self.match_relaxation(relaxation, rel) {
                        Ok(r) => {
                            matched_relaxations.push(r);
                        }
                        Err(failure) => {
                            failed_matches.push(failure);
                        }
                    };
                });

                let m = match matched_relaxations.len() {
                    0 => RelaxationMatchResult::AllFailed(failed_matches),
                    1 => RelaxationMatchResult::Matched(matched_relaxations.pop().unwrap()),
                    _ => RelaxationMatchResult::Ambiguous(matched_relaxations),
                };

                self.accept(&m);

                m
            })
            .collect();

        RelaxationGroup {
            match_results,
            is_complete: group.is_complete_group(),
        }
    }

    fn resolve_group<A: Arch>(
        &self,
        mut relaxation_group: RelaxationGroup<'data, A>,
    ) -> ResolvedGroup<'data, A> {
        let mut reference = None;
        let mut error = None;

        if relaxation_group.is_complete {
            if let Some(matches) = relaxation_group.matches_if_ok() {
                if matches_are_compatible(&matches) {
                    match self.read_reference(&matches) {
                        Ok(r) => reference = Some(r),
                        Err(e) => error = Some(e),
                    }
                }
            }
        }

        if let Some(reference) = reference.as_ref() {
            relaxation_group.eliminate_alt_r_types(reference);
        }

        let mut annotations = relaxation_group
            .match_results
            .iter()
            .flat_map(|r| r.annotations())
            .collect_vec();

        if let Some(e) = error {
            annotations.push(Annotation {
                offset_in_section: relaxation_group.end_offset(),
                kind: AnnotationKind::Error(e.to_string()),
            });
        }

        ResolvedGroup {
            start: relaxation_group.start_offset(),
            end: relaxation_group.end_offset(),
            relaxations: Some(relaxation_group),
            annotations,
            reference: reference.unwrap_or(Reference {
                referent: Referent::Unknown,
                indirection: Default::default(),
            }),
            trace: TraceOutput::default(),
        }
    }

    fn accept<A: Arch>(&mut self, matched_relaxation: &RelaxationMatchResult<A>) {
        self.previous_end = matched_relaxation.end();
        self.next_modifier = matched_relaxation.next_modifier();
    }

    /// Returns whether section bytes are equal to the original input file from `self.previous_end`
    /// up to, but not including `offset`.
    fn is_equal_up_to(&self, offset: u64) -> bool {
        (self.section_bytes.is_none() && self.original_data.is_empty())
            || self.section_bytes.is_some_and(|b| {
                b[self.previous_end as usize..offset as usize]
                    == self.original_data[self.previous_end as usize..offset as usize]
            })
    }

    fn symtab_entry_for_relocation(
        &self,
        runtime_relocation: &object::Relocation,
    ) -> Option<&SymtabEntryInfo<'data>> {
        if let object::RelocationTarget::Symbol(symbol_index) = runtime_relocation.target() {
            return self.bin.address_index.dynamic_symbols.get(symbol_index.0);
        }

        None
    }
}

/// Returns whether the matches have the same referent and addend. Our mechanism of grouping
/// relocations is somewhat flawed in that unrelated relocations can end up being grouped if they're
/// adjacent. For now, we ignore any groups where these don't match.
fn matches_are_compatible<A: Arch>(matches: &[RelaxationMatch<'_, A>]) -> bool {
    let mut previous_addend = None;
    let mut previous_referent = None;

    for m in matches {
        if previous_addend.is_some_and(|prev| prev != m.addend) {
            return false;
        }

        if previous_referent.is_some_and(|prev| prev != m.original_referent) {
            return false;
        }

        previous_addend = Some(m.addend);
        previous_referent = Some(m.original_referent);
    }

    true
}

/// Returns what kind of value we can expect when we extract the value written by a relocation.
fn value_kind_for_relocation<A: Arch>(
    relocation_kind: RelocationKind,
    address_index: &AddressIndex,
) -> Option<ValueKind> {
    let kind = match relocation_kind {
        RelocationKind::Absolute
        | RelocationKind::AbsoluteAArch64
        | RelocationKind::AbsoluteSet
        | RelocationKind::AbsoluteSetWord6
        | RelocationKind::AbsoluteAddition
        | RelocationKind::AbsoluteSubtraction
        | RelocationKind::AbsoluteSubtractionWord6 => {
            if address_index.is_relocatable() {
                ValueKind::Unwrapped(BasicValueKind::AbsoluteValue)
            } else {
                return None;
            }
        }
        RelocationKind::Relative
        | RelocationKind::RelativeRiscVLow12
        | RelocationKind::SymRelGotBase => {
            return None;
        }
        RelocationKind::PltRelative | RelocationKind::PltRelGotBase => ValueKind::OptionalPlt,
        RelocationKind::Got | RelocationKind::GotRelGotBase | RelocationKind::GotRelative => {
            ValueKind::Got(BasicValueKind::Pointer)
        }
        RelocationKind::DtpOff => ValueKind::Unwrapped(BasicValueKind::TlsOffset),
        RelocationKind::TpOff => ValueKind::Unwrapped(A::get_basic_value_for_tp_offset()),
        RelocationKind::GotTpOff
        | RelocationKind::GotTpOffGot
        | RelocationKind::GotTpOffGotBase => ValueKind::Got(BasicValueKind::TlsOffset),
        RelocationKind::TlsDesc | RelocationKind::TlsDescGot | RelocationKind::TlsDescGotBase => {
            // The TLSDESC structure is stored in the GOT. We should perhaps treat this as
            // Unwrapped(TlsDesc), however the code to read dynamic relocations like TLSDESC is
            // currently in the GOT-dereferencing code.
            ValueKind::Got(BasicValueKind::TlsDesc)
        }
        RelocationKind::TlsLd | RelocationKind::TlsLdGot | RelocationKind::TlsLdGotBase => {
            // Similar to TlsDesc, this is a value stored in the GOT.
            ValueKind::Got(BasicValueKind::TlsModuleId)
        }
        RelocationKind::TlsGd | RelocationKind::TlsGdGot | RelocationKind::TlsGdGotBase => {
            // Same as above.
            ValueKind::Got(BasicValueKind::TlsGd)
        }
        RelocationKind::TlsDescCall
        | RelocationKind::None
        | RelocationKind::PairSubtraction
        | RelocationKind::Alignment => {
            return None;
        }
    };

    Some(kind)
}

/// Returns a map from symbol name to `SymbolVersions`. This gives us the address of that symbol
/// each file, or tells us that the symbol has 0 or more than 1 definition in at least one file.
fn symbol_versions_by_name<'data>(
    binaries: &'data [Binary<'data>],
    layout: &IndexedLayout<'data>,
) -> HashMap<&'data [u8], SymbolVersions> {
    // Populate our map with eligible unique symbols from the input files.
    let mut by_name: HashMap<&[u8], SymbolVersions> = layout
        .symbol_name_to_section_id
        .iter()
        .filter_map(|(name, symbol_info)| {
            let section = layout.get_elf_section(symbol_info.section_id).ok()?;

            // Merge sections are ignored, since they're split before copying, so can't be compared
            // 1:1 between output files.
            if is_merge_section(&section)
                || section.size() == 0
                || !SUPPORTED_SECTION_KINDS.contains(&section.kind())
            {
                None
            } else {
                let versions = SymbolVersions {
                    original: *symbol_info,
                    addresses_by_binary: Vec::with_capacity(binaries.len()),
                };

                Some((*name, versions))
            }
        })
        .collect();

    // Try to find those same symbols in all the output files.
    for (object_index, obj) in binaries.iter().enumerate() {
        for sym in obj.elf_file.symbols() {
            let Ok(name) = sym.name_bytes() else { continue };

            if let std::collections::hash_map::Entry::Occupied(mut entry) = by_name.entry(name) {
                if entry.get().addresses_by_binary.len() == object_index {
                    entry.get_mut().addresses_by_binary.push(sym.address());
                } else {
                    // One of the output files didn't define this symbol, remove it from
                    // consideration.
                    entry.remove_entry();
                }
            }
        }
    }

    // Clear any records that are incomplete.
    let num_objects = binaries.len();
    by_name.retain(|_, v| v.addresses_by_binary.len() == num_objects);

    if let Ok(fn_name) = std::env::var(SHOW_FUNCTION_ENV) {
        by_name.retain(|name, _versions| *name == fn_name.as_bytes());
    }

    by_name
}

/// Returns whether the supplied section has the merge flag set. Merge sections aren't copied in
/// their entirety, so need special handling.
fn is_merge_section(section: &ElfSection64<LittleEndian>) -> bool {
    section.elf_section_header().sh_flags(LittleEndian) as u32 & object::elf::SHF_MERGE != 0
}

/// Returns information about sections where we can uniquely locate that section in each input file
/// based on the supplied symbols.
fn unified_sections_from_symbols<'data>(
    report: &mut Report,
    symbol_versions_by_name: HashMap<&'data [u8], SymbolVersions>,
    layout: &IndexedLayout,
    binaries: &[Binary],
) -> HashMap<InputSectionId, SectionVersions<'data>> {
    // Locate the start of the input section for each unique symbol. An input section may contain
    // multiple symbols and we want to make sure that we only diff that section once.

    let mut matched_sections = HashMap::new();

    for (symbol_name, versions) in symbol_versions_by_name {
        let unify_result = unify_symbol_section(
            &mut matched_sections,
            symbol_name,
            versions,
            binaries,
            layout,
        );

        if let Err(error) = unify_result {
            report.add_diff(Diff {
                key: format!("error.{}", String::from_utf8_lossy(symbol_name)),
                values: DiffValues::PreFormatted(error.to_string()),
            });
        }
    }

    matched_sections
}

/// Use `symbol_versions` to populate `matched_sections`.
fn unify_symbol_section<'data>(
    matched_sections: &mut HashMap<InputSectionId, SectionVersions<'data>>,
    symbol_name: &'data [u8],
    mut symbol_versions: SymbolVersions,
    binaries: &[Binary],
    layout: &IndexedLayout,
) -> Result {
    let mut addresses_by_object = core::mem::take(&mut symbol_versions.addresses_by_binary);

    // Ignore ifuncs, since linkers are inconsistent with what the ifunc symbol ends up pointing to.
    if symbol_versions.original.is_ifunc {
        return Ok(());
    }

    // Compute the addresses of the start of the input section in each object by subtracting the
    // offset within the section from each symbol's address.
    for a in &mut addresses_by_object {
        *a = a
            .checked_sub(symbol_versions.original.offset_in_section)
            .context("Underflow when computing section start")?;
    }

    match matched_sections.entry(symbol_versions.original.section_id) {
        std::collections::hash_map::Entry::Occupied(mut occupied_entry) => {
            let existing = occupied_entry.get_mut();

            existing.verify_consistent(&addresses_by_object, symbol_name, binaries, layout)?;

            // In order to give deterministic reports, we use the first symbol name for a
            // section when sorted alphabetically.
            if symbol_name < existing.found_via_symbol {
                existing.found_via_symbol = symbol_name;
            }
        }
        std::collections::hash_map::Entry::Vacant(vacant_entry) => {
            vacant_entry.insert(SectionVersions {
                addresses_by_binary: addresses_by_object,
                found_via_symbol: symbol_name,
                input_section_id: symbol_versions.original.section_id,
            });
        }
    }

    Ok(())
}

/// Matches symbols with the same name from each of our input files.
struct SymbolVersions {
    original: SymbolInfo,

    /// The addresses of the symbol in each input file.
    addresses_by_binary: Vec<u64>,
}

/// An input section for which we know where it was placed in each of the binary files.
#[derive(Clone)]
struct SectionVersions<'data> {
    /// The address of this section in each of our binaries.
    addresses_by_binary: Vec<u64>,

    /// The symbol via which we located this section. This is only used for reporting. This may not
    /// be the only or even the first symbol in this section.
    found_via_symbol: &'data [u8],

    input_section_id: InputSectionId,
}

impl<'data> SectionVersions<'data> {
    fn original_section<'layout>(
        &self,
        layout: &'layout IndexedLayout<'data>,
    ) -> Result<ElfSection64<'data, 'layout, LittleEndian>> {
        layout.get_elf_section(self.input_section_id)
    }

    /// Check that the section addresses are all the same as what we found previously. Otherwise,
    /// report an error.
    fn verify_consistent(
        &self,
        addresses_by_binary: &[u64],
        symbol_name: &[u8],
        binaries: &[Binary<'_>],
        layout: &IndexedLayout,
    ) -> Result {
        for (file_number, (&a, &b)) in self
            .addresses_by_binary
            .iter()
            .zip(addresses_by_binary)
            .enumerate()
        {
            if a != b {
                bail!(
                    "Symbols `{existing_sym}` and `{new_sym}` in `{name}` yield \
                        inconsistent addresses for section `{section_name}` in {input_file}: \
                        0x{a:x?} vs 0x{b:x?}",
                    input_file = layout.input_file_for_section(self.input_section_id),
                    existing_sym = String::from_utf8_lossy(self.found_via_symbol),
                    new_sym = String::from_utf8_lossy(symbol_name),
                    section_name = layout.get_elf_section(self.input_section_id)?.name()?,
                    name = &binaries[file_number],
                );
            }
        }

        Ok(())
    }
}

pub(crate) fn validate_indexes(bin: &Binary) -> Result {
    if let Some(error) = &bin.address_index.index_error {
        bail!("{error}");
    }
    Ok(())
}

pub(crate) fn validate_got_plt(bin: &Binary) -> Result {
    let Some(dynamic) = bin.address_index.dynamic_segment_address else {
        return Ok(());
    };
    let got_plt_sec = bin
        .section_by_name(GOT_PLT_SECTION_NAME_STR)
        .context(".got.plt missing")?;
    let got_plt: &[u64] = object::slice_from_all_bytes(got_plt_sec.data()?)
        .map_err(|_| anyhow!("Invalid .got.plt"))?;
    if got_plt.len() < 3 {
        bail!(".got.plt is too short");
    }
    if got_plt[0] != dynamic {
        bail!("First entry of .got.plt should point to .dynamic");
    }
    if got_plt[1] != 0 || got_plt[2] != 0 {
        bail!(".got.plt[1] and .got.plt[2] are reserved and should be zero");
    }

    Ok(())
}

const ORIG: &str = "ORIG";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SymtabEntryInfo<'data> {
    name: SymbolName<'data>,
    is_weak: bool,
    visibility: Visibility,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolName<'data> {
    bytes: &'data [u8],
    version: Option<&'data [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Visibility {
    Default,
    Protected,
    Hidden,
    Other(u8),
}

#[derive(Clone, Copy)]
enum Data<'data> {
    Bytes(&'data [u8]),
    Bss,
}

impl std::fmt::Debug for SymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.bytes))?;
        if let Some(version) = self.version {
            write!(f, "@{}", String::from_utf8_lossy(version))?;
        }
        Ok(())
    }
}

pub(crate) struct AddressIndex<'data> {
    plt_indexes: Vec<PltIndex<'data>>,
    got_tables: Vec<GotIndex<'data>>,
    index_error: Option<anyhow::Error>,
    jmprel_address: Option<u64>,
    versym_address: Option<u64>,
    dynamic_segment_address: Option<u64>,
    dynamic_relocations_by_address: HashMap<u64, object::Relocation>,
    dynamic_relocations_by_symbol_index: HashMap<object::SymbolIndex, Vec<object::Relocation>>,
    tls_segment_size: u64,

    /// GOT addresses for each JMPREL relocation by their index.
    jmprel_got_addresses: Vec<u64>,

    /// The address of the start of the .got section.
    got_base_address: Option<u64>,

    /// Version names by their index.
    verdef: Vec<Option<&'data [u8]>>,
    verneed: Vec<Option<&'data [u8]>>,

    /// Dynamic symbol names by their index.
    dynamic_symbols: Vec<SymtabEntryInfo<'data>>,
    bin_attributes: BinAttributes,

    symbols_by_address: HashMap<u64, Vec<object::SymbolIndex>>,
}

struct PltIndex<'data> {
    plt_base: u64,
    entry_length: u64,
    bytes: &'data [u8],
}

impl PltIndex<'_> {
    /// Returns the address of the GOT entry for the specified PLT address or None if the supplied
    /// address isn't a valid PLT entry in this index.
    fn lookup_got_address<A: Arch>(
        &self,
        plt_address: u64,
        index: &AddressIndex,
    ) -> Result<Option<u64>> {
        if !(self.plt_base..self.plt_base + self.bytes.len() as u64).contains(&plt_address) {
            return Ok(None);
        }

        let offset = plt_address - self.plt_base;

        if self.entry_length != 0 && !offset.is_multiple_of(self.entry_length) {
            bail!(
                "PLT address 0x{plt_address:x} is not aligned to 0x{:x}",
                self.entry_length
            );
        }

        let plt_entry = if self.entry_length == 0 {
            // Sometimes linkers don't set the entry size on PLT sections. In that case, we try both
            // size 8 and if that fails, try size 16.
            self.decode_plt_entry_with_size::<A>(offset, 8)
                .or_else(|| self.decode_plt_entry_with_size::<A>(offset, 16))
        } else {
            self.decode_plt_entry_with_size::<A>(offset, self.entry_length)
        }
        .with_context(|| format!("Unrecognised PLT entry format at 0x{plt_address:x}"))?;

        let got_address = match plt_entry {
            PltEntry::DerefJmp(address) => address,
            PltEntry::JumpSlot(slot_index) => index
                .jmprel_got_addresses
                .get(slot_index as usize)
                .copied()
                .with_context(|| {
                    format!(
                        "Invalid jump slot index {slot_index} out of {}",
                        index.jmprel_got_addresses.len()
                    )
                })?,
        };

        Ok(Some(got_address))
    }

    fn decode_plt_entry_with_size<A: Arch>(
        &self,
        offset: u64,
        entry_size: u64,
    ) -> Option<PltEntry> {
        let entry_bytes = &self.bytes[offset as usize..(offset + entry_size) as usize];
        A::decode_plt_entry(entry_bytes, self.plt_base, offset)
    }
}

impl<'data> AddressIndex<'data> {
    pub(crate) fn new(elf_file: &'data ElfFile64<'data>) -> Self {
        let mut info = Self {
            index_error: None,
            jmprel_address: None,
            versym_address: None,
            dynamic_segment_address: None,
            got_base_address: None,
            tls_segment_size: get_tls_segment_size(elf_file),
            plt_indexes: Default::default(),
            got_tables: Default::default(),
            verdef: Default::default(),
            verneed: Default::default(),
            dynamic_symbols: Default::default(),
            jmprel_got_addresses: Vec::new(),
            dynamic_relocations_by_address: Default::default(),
            bin_attributes: BinAttributes {
                // These may be overridden in `index_dynamic`.
                output_kind: if elf_file.kind() == ObjectKind::Executable {
                    OutputKind::Executable
                } else {
                    OutputKind::SharedObject
                },
                relocatability: Relocatability::NonRelocatable,
                link_type: LinkType::Static,
            },
            dynamic_relocations_by_symbol_index: Default::default(),
            symbols_by_address: index_symbols_by_address(elf_file),
        };

        if let Err(error) = info.build_indexes(elf_file) {
            info.index_error = Some(error);
        }
        info
    }

    fn build_indexes(&mut self, elf_file: &ElfFile64<'data>) -> Result {
        self.index_dynamic(elf_file);
        self.verdef = Self::index_verdef(elf_file)?;
        self.verneed = Self::index_verneed(elf_file)?;
        self.dynamic_symbols = self.index_dynamic_symbols(elf_file)?;
        self.index_got_tables(elf_file).unwrap();
        self.index_relocations(elf_file);
        self.index_plt_sections(elf_file)?;
        Ok(())
    }

    fn index_verdef(elf_file: &ElfFile64<'data>) -> Result<Vec<Option<&'data [u8]>>> {
        let e = LittleEndian;
        let mut versions = Vec::new();

        let maybe_verdef = elf_file
            .sections()
            .find_map(|section| {
                section
                    .elf_section_header()
                    .gnu_verdef(e, elf_file.data())
                    .transpose()
            })
            .transpose()?;

        let Some((mut verdef_iterator, strings_index)) = maybe_verdef else {
            return Ok(versions);
        };

        let strings = elf_file
            .elf_section_table()
            .strings(e, elf_file.data(), strings_index)?;

        while let Some((_verdef, mut aux_iterator)) = verdef_iterator.next()? {
            // We don't need verdef parent here, so take only the first entry
            if let Some(aux) = aux_iterator.next()? {
                let name = aux.name(e, strings)?;
                versions.push(Some(name));
            }
        }

        Ok(versions)
    }

    fn index_verneed(elf_file: &ElfFile64<'data>) -> Result<Vec<Option<&'data [u8]>>> {
        let e = LittleEndian;
        let mut versions = Vec::new();

        let maybe_verneed = elf_file
            .sections()
            .find_map(|section| {
                section
                    .elf_section_header()
                    .gnu_verneed(e, elf_file.data())
                    .transpose()
            })
            .transpose()?;

        let Some((mut verneed_iterator, strings_index)) = maybe_verneed else {
            return Ok(versions);
        };

        let strings = elf_file
            .elf_section_table()
            .strings(e, elf_file.data(), strings_index)?;

        while let Some((_verneed, mut aux_iterator)) = verneed_iterator.next()? {
            while let Some(aux) = aux_iterator.next()? {
                let name = aux.name(e, strings)?;
                let index = aux.vna_other.get(e) as usize;
                if index >= versions.len() {
                    versions.resize(index + 1, None);
                }
                versions[index] = Some(name);
            }
        }

        Ok(versions)
    }

    fn index_dynamic_symbols(
        &self,
        elf_file: &ElfFile64<'data>,
    ) -> Result<Vec<SymtabEntryInfo<'data>>> {
        let symbol_version_indexes: Option<&[u16]> = self
            .versym_address
            .and_then(|address| {
                elf_file
                    .sections()
                    .find(|section| section.address() == address)
            })
            .and_then(|section| section.data().ok())
            .and_then(|data| object::slice_from_all_bytes(data).ok());

        let mut dynamic_symbol_names = Vec::new();
        let mut max_index = 0;

        for sym in elf_file.dynamic_symbols() {
            let sym_index = sym.index().0;
            max_index = max_index.max(sym_index);
            let version_index = symbol_version_indexes
                .and_then(|indexes| indexes.get(sym_index))
                .copied();

            let version: Option<&[u8]> = match version_index {
                Some(object::elf::VER_NDX_LOCAL) => Some(b"*local*"),
                Some(object::elf::VER_NDX_GLOBAL) => Some(b"*global*"),
                Some(version_index) if version_index > object::elf::VER_NDX_GLOBAL => self
                    .verdef
                    .get(version_index as usize - 1)
                    .or_else(|| self.verneed.get(version_index as usize))
                    .copied()
                    .flatten(),
                _ => None,
            };

            let name_bytes = sym.name_bytes()?;
            let name = SymbolName {
                bytes: name_bytes,
                version,
            };

            let visibility = Visibility::from_sym(sym.elf_symbol());

            ensure!(
                visibility != Visibility::Hidden,
                "Dynamic symbol {name} has unexpected hidden visibility"
            );

            while dynamic_symbol_names.len() < sym_index {
                dynamic_symbol_names.push(SymtabEntryInfo {
                    name: SymbolName {
                        bytes: &[],
                        version: None,
                    },
                    is_weak: false,
                    visibility: Visibility::Default,
                });
            }

            dynamic_symbol_names.push(SymtabEntryInfo {
                name,
                is_weak: sym.is_weak(),
                visibility,
            });
        }

        if let Some(versym) = symbol_version_indexes {
            let versym_len = versym.len();
            let num_symbols = max_index + 1;
            if versym_len != num_symbols {
                bail!(".gnu.version contains {versym_len}, but .dynsym contains {num_symbols}");
            }
        }

        Ok(dynamic_symbol_names)
    }

    fn index_relocations(&mut self, elf_file: &ElfFile64<'data>) {
        if let Some(dynamic_relocations) = elf_file.dynamic_relocations() {
            for (_, rel) in dynamic_relocations {
                if let RelocationTarget::Symbol(symbol_index) = rel.target() {
                    self.dynamic_relocations_by_symbol_index
                        .entry(symbol_index)
                        .or_default()
                        .push(rel);
                }
            }
        }

        if let Some(dynamic_relocations) = elf_file.dynamic_relocations() {
            self.dynamic_relocations_by_address
                .extend(dynamic_relocations);
        }

        for section in elf_file.sections() {
            self.dynamic_relocations_by_address
                .extend(section.relocations());
        }
    }

    fn index_plt_sections(&mut self, elf_file: &ElfFile64<'data>) -> Result {
        self.index_plt_named(elf_file, PLT_SECTION_NAME_STR)?;
        self.index_plt_named(elf_file, PLT_SEC_SECTION_NAME_STR)?;
        self.index_plt_named(elf_file, PLT_GOT_SECTION_NAME_STR)?;
        self.index_plt_named(elf_file, IPLT_SECTION_NAME_STR)?;
        Ok(())
    }

    fn index_plt_named(&mut self, elf_file: &ElfFile64<'data>, section_name: &str) -> Result {
        let Some(section) = elf_file.section_by_name(section_name) else {
            return Ok(());
        };

        let Ok(bytes) = section.data() else {
            return Ok(());
        };

        let entry_length = section.elf_section_header().sh_entsize(LittleEndian) as usize;

        if ![0, 8, 0x10].contains(&entry_length) {
            bail!("{section_name} has unrecognised entry length {entry_length}");
        }

        let plt_base = section.address();

        self.plt_indexes.push(PltIndex {
            bytes,
            plt_base,
            entry_length: entry_length as u64,
        });

        Ok(())
    }

    fn index_got_tables(&mut self, elf_file: &ElfFile64<'data>) -> Result {
        self.got_tables = [GOT_PLT_SECTION_NAME_STR, GOT_SECTION_NAME_STR]
            .iter()
            .filter_map(|table_name| Self::index_got_table(elf_file, table_name).transpose())
            .try_collect()?;

        self.got_base_address = self.got_tables.first().map(|t| t.address_range.start);

        Ok(())
    }

    fn index_got_table(
        elf_file: &ElfFile64<'data>,
        table_name: &str,
    ) -> Result<Option<GotIndex<'data>>> {
        let Some(got_section) = elf_file.section_by_name(table_name) else {
            return Ok(None);
        };

        let data = got_section.data()?;
        let raw_entries: &[u64] = if data.is_empty() {
            // An empty .got may not be aligned, so we avoid calling object::slice_from_bytes.
            &[]
        } else {
            let entry_size = size_of::<u64>();
            object::slice_from_bytes(data, data.len() / entry_size)
                .unwrap()
                .0
        };

        let base = got_section.address();
        Ok(Some(GotIndex {
            address_range: base..base + data.len() as u64,
            entries: raw_entries,
        }))
    }

    fn index_dynamic(&mut self, elf_file: &ElfFile64) {
        let e = LittleEndian;

        let dynamic_segment = elf_file
            .elf_program_headers()
            .iter()
            .find(|seg| seg.p_type(LittleEndian) == object::elf::PT_DYNAMIC);

        self.dynamic_segment_address = dynamic_segment.map(|seg| seg.p_vaddr(e));

        if elf_file.elf_header().e_type(LittleEndian) == object::elf::ET_DYN {
            self.bin_attributes.relocatability = Relocatability::Relocatable;
        }

        if dynamic_segment.is_none() {
            self.bin_attributes.output_kind = OutputKind::Executable;
        };

        dynamic_segment
            .and_then(|seg| seg.data(LittleEndian, elf_file.data()).ok())
            .and_then(|dynamic_table_data| {
                object::slice_from_all_bytes::<object::elf::Dyn64<LittleEndian>>(dynamic_table_data)
                    .ok()
            })
            .unwrap_or_default()
            .iter()
            .for_each(|entry| match entry.d_tag.get(e) as u32 {
                object::elf::DT_JMPREL => {
                    self.jmprel_address = Some(entry.d_val.get(e));
                }
                object::elf::DT_VERSYM => {
                    self.versym_address = Some(entry.d_val.get(e));
                }
                object::elf::DT_FLAGS_1 => {
                    if entry.d_val.get(e) & u64::from(object::elf::DF_1_PIE) != 0 {
                        self.bin_attributes.output_kind = OutputKind::Executable;
                    }
                }
                object::elf::DT_NEEDED => {
                    self.bin_attributes.link_type = LinkType::Dynamic;
                }
                _ => {}
            });
    }

    fn plt_to_got_address<A: Arch>(&self, plt_address: u64) -> Result<Option<u64>> {
        self.plt_indexes
            .iter()
            .find_map(|index| index.lookup_got_address::<A>(plt_address, self).transpose())
            .transpose()
    }

    fn is_got_address(&self, address: u64) -> bool {
        self.got_tables
            .iter()
            .any(|t| t.address_range.contains(&address))
    }

    pub(crate) fn symbols_at_address(&self, address: u64) -> &[object::SymbolIndex] {
        self.symbols_by_address
            .get(&address)
            .map(|s| s.as_slice())
            .unwrap_or_default()
    }

    pub(crate) fn relocation_at_address(&self, address: u64) -> Option<&object::Relocation> {
        self.dynamic_relocations_by_address.get(&address)
    }

    fn dereference_got_address<R: RType>(
        &self,
        got_address: u64,
        relocation_kind: RelocationKind,
        bin: &Binary<'data>,
        expected_value_kind: BasicValueKind,
    ) -> Result<Referent<'data, R>> {
        let table = self
            .got_tables
            .iter()
            .find(|table| table.address_range.contains(&got_address))
            .context("Address isn't in any GOT tables")?;

        table.dereference_got_address(got_address, relocation_kind, bin, expected_value_kind)
    }

    fn is_relocatable(&self) -> bool {
        self.bin_attributes.relocatability == Relocatability::Relocatable
    }
}

fn get_tls_segment_size(elf_file: &ElfFile64) -> u64 {
    elf_file
        .elf_program_headers()
        .iter()
        .find_map(|header| {
            (header.p_type(LittleEndian) == object::elf::PT_TLS)
                .then(|| header.p_memsz(LittleEndian))
        })
        .unwrap_or(0)
}

fn index_symbols_by_address(elf_file: &ElfFile64) -> HashMap<u64, Vec<object::SymbolIndex>> {
    let mut out: HashMap<u64, Vec<object::SymbolIndex>> = HashMap::new();

    for sym in elf_file.symbols() {
        out.entry(sym.address()).or_default().push(sym.index());
    }

    out
}

struct GotIndex<'data> {
    /// The addresses covered by this table.
    address_range: Range<u64>,

    entries: &'data [u64],
}

impl<'data> GotIndex<'data> {
    fn dereference_got_address<R: RType>(
        &self,
        got_address: u64,
        relocation_kind: RelocationKind,
        bin: &Binary<'data>,
        expected_value_kind: BasicValueKind,
    ) -> Result<Referent<'data, R>> {
        let index = &bin.address_index;

        let offset = got_address
            .checked_sub(self.address_range.start)
            .context("got_address outside index range")?;

        let entry_size = size_of::<u64>() as u64;
        if !offset.is_multiple_of(entry_size) {
            bail!("Unaligned reference to GOT 0x{got_address:x}");
        }

        if let Some(rel) = index.dynamic_relocations_by_address.get(&got_address) {
            let r_type = get_r_type::<R>(rel);

            let dynamic_relocation_kind = r_type
                .dynamic_relocation_kind()
                .with_context(|| format!("Unsupported dynamic relocation {r_type}"))?;

            let symbol = if let object::RelocationTarget::Symbol(symbol_index) = rel.target() {
                Some(
                    index
                        .dynamic_symbols
                        .get(symbol_index.0)
                        .context("Symbol index out of range")?,
                )
            } else {
                None
            };

            match dynamic_relocation_kind {
                DynamicRelocationKind::Relative => {
                    Ok(Referent::UnmatchedAddress(UnmatchedAddress {
                        address: rel.addend() as u64,
                        ..Default::default()
                    }))
                }
                DynamicRelocationKind::Irelative => Ok(Referent::IFunc(determine_ifunc_name(
                    rel.addend() as u64,
                    bin,
                ))),
                DynamicRelocationKind::DtpMod => {
                    match (expected_value_kind, symbol) {
                        (BasicValueKind::TlsModuleId, None) => Ok(Referent::TlsModuleId),
                        (BasicValueKind::TlsModuleId, Some(symbol)) => {
                            bail!("Expected TLSLD, but found DTPMOD with symbol (`{symbol}`)");
                        }
                        (BasicValueKind::TlsGd, Some(symbol)) => Ok(Referent::TlsGd(*symbol)),
                        (BasicValueKind::TlsGd, None) => {
                            // There's no symbol associated with the DTPMOD relocation, so it's a TLS
                            // variable within the current DSO. Read the next word of data to get the
                            // offset.
                            let tls_offset =
                                read_word_at(bin.elf_file, got_address + size_of::<u64>() as u64)?
                                    .context("Short read after DTPMOD")?
                                    as i64;
                            Ok(Referent::UnmatchedTlsOffset(tls_offset))
                        }
                        (other, _) => bail!("Unexpected DTPMOD when looking for {other:?}"),
                    }
                }
                DynamicRelocationKind::TpOff if symbol.is_none() => {
                    Ok(Referent::UnmatchedTlsOffset(rel.addend()))
                }
                DynamicRelocationKind::TlsDesc => {
                    if let Some(symbol) = symbol {
                        Ok(Referent::TlsDesc(*symbol))
                    } else {
                        Ok(Referent::UnmatchedTlsOffset(rel.addend()))
                    }
                }
                _ => {
                    let symbol = symbol.with_context(|| format!("{r_type} without symbol"))?;

                    Ok(Referent::DynamicRelocation(DynamicRelocation {
                        entry: *symbol,
                        r_type,
                        addend: rel.addend(),
                    }))
                }
            }
        } else {
            // No dynamic relocation, just read from the original file data.
            let raw_value = *self
                .entries
                .get((offset / entry_size) as usize)
                .context("got_address past end of index range")?;

            match relocation_kind {
                RelocationKind::GotTpOff
                | RelocationKind::GotTpOffGot
                | RelocationKind::GotTpOffGotBase => {
                    Ok(Referent::UnmatchedTlsOffset(raw_value as i64))
                }
                RelocationKind::TlsDescCall => Ok(Referent::TlsDescCall),
                RelocationKind::Absolute
                | RelocationKind::AbsoluteAArch64
                | RelocationKind::AbsoluteSet
                | RelocationKind::AbsoluteSetWord6
                | RelocationKind::AbsoluteAddition
                | RelocationKind::AbsoluteSubtraction
                | RelocationKind::AbsoluteSubtractionWord6
                | RelocationKind::Relative
                | RelocationKind::RelativeRiscVLow12
                | RelocationKind::SymRelGotBase
                | RelocationKind::GotRelGotBase
                | RelocationKind::Got
                | RelocationKind::PltRelGotBase
                | RelocationKind::PltRelative
                | RelocationKind::GotRelative
                | RelocationKind::None
                | RelocationKind::PairSubtraction
                | RelocationKind::Alignment => Ok(Referent::Absolute(raw_value)),
                RelocationKind::TlsGd
                | RelocationKind::TlsGdGot
                | RelocationKind::TlsGdGotBase
                | RelocationKind::TlsLd
                | RelocationKind::TlsLdGot
                | RelocationKind::TlsLdGotBase
                | RelocationKind::DtpOff
                | RelocationKind::TpOff
                | RelocationKind::TlsDesc
                | RelocationKind::TlsDescGot
                | RelocationKind::TlsDescGotBase => {
                    bail!("Missing dynamic relocation for {relocation_kind:?}")
                }
            }
        }
    }
}

/// Returns the name of the ifunc resolver given the resolver address. We choose to return the name
/// of the resolver rather than the ifunc name because GNU ld and lld are inconsistent with where
/// they point the symbol for the ifunc, whereas the resolver's symbol consistently points at the
/// address of the resolver.
fn determine_ifunc_name<'data>(address: u64, bin: &Binary<'data>) -> Option<SymbolName<'data>> {
    bin.address_index
        .symbols_at_address(address)
        .iter()
        .filter_map(|symbol_index| {
            let symbol = bin.elf_file.symbol_by_index(*symbol_index).ok()?;

            // We're likely to get symbols of type STT_GNU_IFUNC. The resolver should be just a
            // regular function and that's what we want.
            if symbol.elf_symbol().st_type() != object::elf::STT_FUNC {
                return None;
            }

            Some(SymbolName {
                bytes: symbol.name_bytes().ok()?,
                version: None,
            })
        })
        .max()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DynamicRelocation<'data, R: RType> {
    entry: SymtabEntryInfo<'data>,
    r_type: R,
    addend: i64,
}

/// Attempts to read some data starting at `address` up to the end of the segment.
fn read_segment<'data>(elf_file: &ElfFile64<'data>, address: u64) -> Result<Option<Data<'data>>> {
    // This could well end up needing to be optimised if we end up caring about performance.
    for (seg_index, raw_seg) in elf_file.elf_program_headers().iter().enumerate() {
        let e = LittleEndian;
        if raw_seg.p_type(e) != object::elf::PT_LOAD {
            continue;
        }
        let seg_address = raw_seg.p_paddr(e);
        let seg_len = raw_seg.p_memsz(e);
        let seg_end = seg_address + seg_len;

        if seg_address <= address && address < seg_end {
            let start = (address - seg_address) as usize;
            let file_start = raw_seg.p_offset(e) as usize;
            let file_size = raw_seg.p_filesz(e) as usize;
            let file_end = file_start + file_size;
            let file_bytes = elf_file.data();
            if file_bytes.is_empty() {
                return Ok(Some(Data::Bss));
            }
            let bytes = &file_bytes
                .get(file_start + start..file_end)
                .with_context(|| format!("Invalid ELF segment {seg_index}"))?;
            return Ok(Some(Data::Bytes(bytes)));
        }
    }
    Ok(None)
}

fn read_word_at(elf_file: &ElfFile64, address: u64) -> Result<Option<u64>> {
    let Some(bytes) = read_bytes(elf_file, address, size_of::<u64>() as u64)? else {
        return Ok(None);
    };
    let Some(chunk) = bytes.first_chunk() else {
        return Ok(None);
    };
    Ok(Some(u64::from_le_bytes(*chunk)))
}

fn read_bytes<'data>(
    elf_file: &ElfFile64<'data>,
    address: u64,
    len: u64,
) -> Result<Option<&'data [u8]>> {
    Ok(
        read_segment(elf_file, address)?.and_then(|data| match data {
            Data::Bytes(bytes) => bytes.get(..len as usize),
            Data::Bss => None,
        }),
    )
}

/// Returns bytes starting at `address` up to the end of the containing segment. This is useful when
/// you don't know what length you need to read, e.g. when reading a null-terminated string.
fn read_bytes_starting_at<'data>(
    elf_file: &ElfFile64<'data>,
    address: u64,
) -> Result<Option<&'data [u8]>> {
    Ok(
        read_segment(elf_file, address)?.and_then(|data| match data {
            Data::Bytes(bytes) => Some(bytes),
            Data::Bss => None,
        }),
    )
}

impl Display for SymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            symbolic_demangle::demangle(&String::from_utf8_lossy(self.bytes))
        )?;
        if let Some(version) = self.version {
            write!(f, "@{}", String::from_utf8_lossy(version))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct BinAttributes {
    output_kind: OutputKind,
    relocatability: Relocatability,
    link_type: LinkType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputKind {
    Executable,
    SharedObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Relocatability {
    Relocatable,
    NonRelocatable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkType {
    Dynamic,
    Static,
}

impl BinAttributes {
    fn type_name(self) -> &'static str {
        match (self.output_kind, self.relocatability, self.link_type) {
            (OutputKind::Executable, Relocatability::Relocatable, LinkType::Dynamic) => {
                "dynamic-pie"
            }
            (OutputKind::Executable, Relocatability::Relocatable, LinkType::Static) => "static-pie",
            (OutputKind::Executable, Relocatability::NonRelocatable, LinkType::Dynamic) => {
                "dynamic-non-pie"
            }
            (OutputKind::Executable, Relocatability::NonRelocatable, LinkType::Static) => {
                "static-non-pie"
            }
            (OutputKind::SharedObject, Relocatability::Relocatable, LinkType::Dynamic) => {
                "shared-object"
            }
            (OutputKind::SharedObject, _, _) => "invalid-shared-object",
        }
    }
}

fn relocation_num_bytes(info: RelocationKindInfo) -> usize {
    match info.size {
        linker_utils::elf::RelocationSize::ByteSize(b) => b,
        linker_utils::elf::RelocationSize::BitMasking(mask) => {
            (mask.range.end.div_ceil(8) - mask.range.start / 8) as usize
        }
    }
}

fn read_value(size: RelocationSize, value_bytes: &[u8]) -> Result<u64> {
    match size {
        RelocationSize::ByteSize(8) => Ok(u64::from_le_bytes(
            *value_bytes
                .first_chunk::<8>()
                .context("Invalid relocation offset")?,
        )),
        RelocationSize::ByteSize(4) => Ok(u64::from(u32::from_le_bytes(
            *value_bytes
                .first_chunk::<4>()
                .context("Invalid relocation offset")?,
        ))),
        RelocationSize::ByteSize(0) => Ok(0),
        RelocationSize::ByteSize(other) => bail!("Unsupported relocation size {other}"),
        RelocationSize::BitMasking(BitMask {
            range,
            instruction: insn,
        }) => {
            let (raw_value, _negative) = insn.read_value(value_bytes);
            Ok(raw_value << range.start)
        }
    }
}

impl<A: Arch> Relaxation<A> {
    fn relocation_size(&self) -> Result<RelocationSize> {
        let size = self.new_r_type.relocation_info()?.size;

        if let Some(alt_r_type) = self.alt_r_type {
            let alt_size = alt_r_type.relocation_info()?.size;
            assert_eq!(alt_size, size);
        }

        Ok(size)
    }

    fn relocation_num_bytes(&self) -> Result<usize> {
        let relocation_info = self.new_r_type.relocation_info()?;

        Ok(relocation_num_bytes(relocation_info))
    }
}

fn has_copy_relocation_for_symbol_named<R: RType>(symbol_name: &[u8], bin: &Binary) -> bool {
    bin.name_index
        .dynamic_by_name
        .get(symbol_name)
        .is_some_and(|symbol_indexes| {
            symbol_indexes.iter().any(|symbol_index| {
                bin.address_index
                    .dynamic_relocations_by_symbol_index
                    .get(symbol_index)
                    .is_some_and(|relocations| {
                        relocations.iter().any(|rel| {
                            let r_type = get_r_type::<R>(rel);
                            r_type.dynamic_relocation_kind() == Some(DynamicRelocationKind::Copy)
                        })
                    })
            })
        })
}

fn populate_section_coverage(cov: &mut crate::Coverage, layout: &IndexedLayout<'_>) {
    layout.all_sections_do(|section_info| {
        let Ok(elf_section) = layout.get_elf_section(section_info.section_id) else {
            return;
        };

        let Some(name) = elf_section.name_bytes().ok() else {
            return;
        };

        cov.sections.insert(
            section_info.section_id,
            SectionCoverage {
                original_file: layout
                    .input_file_for_section(section_info.section_id)
                    .identifier
                    .to_owned(),
                name: String::from_utf8_lossy(name).into_owned(),
                num_bytes: elf_section.size(),
                diffed: false,
            },
        );
    });
}

impl Display for SymtabEntryInfo<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.name, f)?;
        if self.is_weak {
            write!(f, " (weak)")?;
        }

        match self.visibility {
            Visibility::Default => {}
            Visibility::Protected => write!(f, " (protected)")?,
            Visibility::Hidden => write!(f, " (hidden)")?,
            Visibility::Other(other) => write!(f, " (vis={other})")?,
        }
        Ok(())
    }
}

impl Display for OutputKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputKind::Executable => write!(f, "executable"),
            OutputKind::SharedObject => write!(f, "shared-object"),
        }
    }
}

impl Visibility {
    fn from_sym(elf_symbol: &object::elf::Sym64<LittleEndian>) -> Visibility {
        match elf_symbol.st_visibility() {
            object::elf::STV_DEFAULT => Visibility::Default,
            object::elf::STV_PROTECTED => Visibility::Protected,
            object::elf::STV_HIDDEN => Visibility::Hidden,
            other => Visibility::Other(other),
        }
    }
}
