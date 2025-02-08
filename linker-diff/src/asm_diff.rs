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
use crate::arch::Arch;
use crate::arch::Instruction;
use crate::arch::PltEntry;
use crate::arch::RType;
use crate::arch::Relaxation;
use crate::arch::RelaxationKind;
use crate::diagnostics::TraceOutput;
use crate::section_map;
use crate::Binary;
use crate::Diff;
use crate::DiffValues;
use crate::ElfFile64;
use crate::Report;
use crate::Result;
use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context as _;
use colored::ColoredString;
use colored::Colorize as _;
use itertools::Itertools as _;
#[allow(clippy::wildcard_imports)]
use linker_utils::elf::secnames::*;
use linker_utils::elf::DynamicRelocationKind;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::RelocationKindInfo;
use linker_utils::relaxation::RelocationModifier;
use object::read::elf::ElfSection64;
use object::read::elf::FileHeader as _;
use object::read::elf::ProgramHeader as _;
use object::read::elf::SectionHeader as _;
use object::LittleEndian;
use object::Object as _;
use object::ObjectSection as _;
use object::ObjectSymbol as _;
use object::RelocationFlags;
use object::RelocationTarget;
use object::SectionKind;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Display;
use std::fmt::Write as _;
use std::ops::Range;

/// Reports differences in sections in particular differences in the relocations that were applied
/// to those sections, although the literal bytes between the relocations are also diffed.
pub(crate) fn report_section_diffs(report: &mut Report, binaries: &[Binary]) {
    // TODO: add support for aarch64 target
    match binaries[0].elf_file.elf_header().e_machine(LittleEndian) {
        object::elf::EM_X86_64 => {
            report_function_diffs_for_arch::<crate::x86_64::X86_64>(report, binaries);
        }
        _ => {}
    }
}

pub(crate) fn report_function_diffs_for_arch<A: Arch>(report: &mut Report, binaries: &[Binary]) {
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

    let by_name = symbol_versions_by_name(binaries, layout);
    let matched_sections = unified_sections_from_symbols(report, by_name, layout, binaries);

    let mut section_ids_to_process: Vec<InputSectionId> =
        matched_sections.keys().copied().collect();

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

    let mut resolutions = Vec::new();

    for (offset, rel) in relocations {
        resolutions.clear();

        diff_literal_bytes::<A>(
            report,
            section_versions,
            layout,
            &mut testers,
            offset.saturating_sub(MAX_RELAX_MODIFY_BEFORE),
        )?;

        let mut orig_trace = TraceOutput::default();

        let original_referent = crate::diagnostics::trace_scope(&mut orig_trace, || {
            get_original_referent(
                &rel,
                layout.input_file_for_section(section_versions.input_section_id),
            )
        })?;

        let original_annotation = OriginalAnnotation {
            success: SuccessAnnotation::<A> {
                r_type: get_r_type(&rel),
                relaxation_kind: None,
                reference: Reference {
                    referent: original_referent,
                    props: ReferenceProperties::default(),
                },
            },
            trace: orig_trace,
        };

        for tester in &mut testers {
            let mut trace = TraceOutput::default();

            let res = crate::diagnostics::trace_scope(&mut trace, || {
                tester.try_resolve(section_kind, offset, &rel, original_referent)
            })?;

            if let Some(mut resolution) = res {
                resolution.trace = trace;

                resolutions.push(resolution);
            }
        }

        // The first resolution (the one from our linker-under-test) must be equal to at least one
        // of the other resolutions.
        if let Some(first) = resolutions.first() {
            let at_least_one_match = resolutions[1..].iter().any(|other| first.matches(other));

            // Ideally we'd successfully match all binaries, however GNU ld when it has PLT
            // relocation for an undefined symbol emits a PLT entry that points to an invalid GOT
            // address. We don't have any good way to match something like that.
            let first_has_match_failure = first.relaxation.is_none();

            if !at_least_one_match || first_has_match_failure {
                report.add_diff(resolution_diff_exec(
                    offset,
                    Some(original_annotation),
                    &resolutions,
                    &testers,
                    section_versions.input_section_id,
                    layout,
                )?);
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

    for tester in testers.iter() {
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
            .map(|_| Resolution {
                relaxation: None,
                annotation: Annotation::<A>::LiteralByteMismatch,
                reference: Reference {
                    referent: Referent::Unknown,
                    props: ReferenceProperties::default(),
                },
                start,
                end,
                next_modifier: RelocationModifier::Normal,
                offset: start,
                trace: TraceOutput::default(),
            })
            .collect_vec();

        report.add_diff(resolution_diff_exec(
            end,
            None,
            &resolutions,
            testers,
            section_versions.input_section_id,
            layout,
        )?);
    }

    Ok(())
}

fn get_r_type<R: RType>(rel: &object::Relocation) -> R {
    let RelocationFlags::Elf { r_type } = rel.flags() else {
        panic!("Unsupported object type (relocation flags)");
    };
    R::from_raw(r_type)
}

/// Represents a diff found in executable code.
struct ExecDiff<'data, A: Arch> {
    offset: u64,
    original_annotation: Option<OriginalAnnotation<'data, A>>,
    resolutions: &'data [Resolution<'data, A>],
    testers: &'data [RelaxationTester<'data>],
    section_id: InputSectionId,
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

        let mut annotation = None;
        let mut trace = TraceOutput::default();

        if let Some(orig) = self.original_annotation.as_ref() {
            annotation = Some(Annotation::Success(orig.success.clone()));
            trace = orig.trace.clone();
        }

        let mut blocks = vec![RelocationInstructionBlock {
            name: ORIG,
            relocation_offset: self.offset,
            annotation,
            trace_messages: Vec::new(),
            section_bytes: original_section.data()?,
            section_address: 0,
            range: range.start..range.end,
            function_info,
            instructions: Default::default(),
            trace,
        }];

        for (res, tester) in self.resolutions.iter().zip(self.testers) {
            let section_bytes = tester
                .section_bytes
                .context("Missing executable section bytes")?;

            let block = RelocationInstructionBlock {
                name: &tester.bin.name,
                relocation_offset: res.offset,
                annotation: Some(res.annotation.clone()),
                trace_messages: tester.bin.trace.messages_in(
                    range.start + tester.section_address..range.end + tester.section_address,
                ),
                section_bytes,
                section_address: tester.section_address,
                range: range.start..range.end,
                function_info,
                instructions: Default::default(),
                trace: res.trace.clone(),
            };

            blocks.push(block);
        }

        for block in &mut blocks {
            let mut trace = TraceOutput::default();

            crate::diagnostics::trace_scope(&mut trace, || {
                block.decode_instructions();
            });

            block.trace.append(trace);
        }

        let maximum_widths = blocks.iter().fold(ColumnWidths::default(), |widths, b| {
            widths.merge(b.widths())
        });

        for block in &blocks {
            block.write_to(f, &maximum_widths)?;
        }

        Ok(())
    }
}

/// Produces a diff showing the different resolutions found for a relocation in some executable
/// code.
fn resolution_diff_exec<A: Arch>(
    offset: u64,
    original_annotation: Option<OriginalAnnotation<A>>,
    resolutions: &[Resolution<A>],
    testers: &[RelaxationTester<'_>],
    section_id: InputSectionId,
    layout: &IndexedLayout,
) -> Result<Diff> {
    let bin_attributes = testers[1].bin.address_index.bin_attributes;

    let key = diff_key_for_res_mismatch(resolutions, original_annotation.as_ref(), bin_attributes);

    let diff = ExecDiff {
        offset,
        original_annotation,
        resolutions,
        testers,
        section_id,
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
                        addend,
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
    resolutions: &[Resolution<A>],
    original_annotation: Option<&OriginalAnnotation<A>>,
    bin_attributes: BinAttributes,
) -> String {
    if resolutions.len() < 2 {
        return "missing-resolutions".to_owned();
    }

    // We might have failed to match one of the reference linker outputs, so find the first
    // reference linker output that we successfully matched.
    let reference = resolutions.iter().skip(1).find_map(|r| r.relaxation);

    match (resolutions[0].relaxation, reference) {
        (Some(r1), Some(r2)) => {
            match (
                original_annotation,
                r1.relaxation_kind.is_no_op(),
                r2.relaxation_kind.is_no_op(),
            ) {
                (Some(orig), true, false) => {
                    format!(
                        "rel.missing-opt.{}.{:?}.{}",
                        orig.success.r_type,
                        r2.relaxation_kind,
                        bin_attributes.type_name()
                    )
                }
                (Some(orig), false, true) => {
                    format!(
                        "rel.extra-opt.{}.{:?}.{}",
                        orig.success.r_type,
                        r1.relaxation_kind,
                        bin_attributes.type_name()
                    )
                }
                _ => format!("rel.{}.{}", r1.new_r_type, r2.new_r_type),
            }
        }
        _ => {
            let failure_kind = |r: &Resolution<A>| match &r.annotation {
                Annotation::Ambiguous(_) => Some("rel.multiple_matches".to_owned()),
                Annotation::MatchFailed(_) => {
                    original_annotation.map(|a| format!("rel.match_failed.{}", a.success.r_type))
                }
                Annotation::Success(_) => None,
                Annotation::LiteralByteMismatch => Some("literal-byte-mismatch".to_owned()),
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

    /// The offset of the relocation within the section.
    relocation_offset: u64,

    annotation: Option<Annotation<'data, A>>,

    trace_messages: Vec<&'data str>,

    /// The bytes of the section.
    section_bytes: &'data [u8],

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
    success: SuccessAnnotation<'data, A>,

    trace: TraceOutput,
}

#[derive(Clone, Debug)]
enum Annotation<'data, A: Arch> {
    Success(SuccessAnnotation<'data, A>),
    Ambiguous(Vec<SuccessAnnotation<'data, A>>),
    MatchFailed(Vec<FailedMatch<A>>),
    LiteralByteMismatch,
}

#[derive(Clone, Debug)]
struct SuccessAnnotation<'data, A: Arch> {
    r_type: A::RType,

    reference: Reference<'data, A::RType>,

    relaxation_kind: Option<<A as Arch>::RelaxationKind>,
}

enum MatchResult<'data, A: Arch> {
    Matched(Resolution<'data, A>),
    Failed(FailedMatch<A>),
}

#[derive(Clone, Debug)]
struct FailedMatch<A: Arch> {
    candidate: Relaxation<A>,
    reason: Cow<'static, str>,
}

impl<A: Arch> FailedMatch<A> {
    fn new(candidate: Relaxation<A>, reason: impl Into<Cow<'static, str>>) -> FailedMatch<A> {
        FailedMatch {
            candidate,
            reason: reason.into(),
        }
    }
}

impl<A: Arch> RelocationInstructionBlock<'_, A> {
    fn widths(&self) -> ColumnWidths {
        ColumnWidths {
            name: self.name.len(),
            address: format!(
                "{:x}",
                self.section_address + self.section_bytes.len() as u64
            )
            .len(),
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
        self.instructions = A::decode_instructions_in_range(
            self.section_bytes,
            self.section_address,
            self.function_info.offset_in_section,
            self.range.clone(),
        );
    }

    fn write_to(&self, f: &mut String, maximum_widths: &ColumnWidths) -> Result {
        let name_width = maximum_widths.name;
        let address_width = maximum_widths.address;

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

            let out = A::instruction_to_string(instruction.raw_instruction);

            let instruction_padding =
                (maximum_widths.instruction_bytes - instruction.bytes.len()) * 3;

            writeln!(f, "{:instruction_padding$}] {}", "", out.purple())?;

            if self.relocation_offset >= instruction_offset
                && self.relocation_offset <= instruction_end
            {
                let num_spaces = name_width
                    + address_width
                    + 7
                    + (self.relocation_offset - instruction_offset) as usize * 3;

                self.write_annotation(f, num_spaces)?;
                self.write_traces(f, maximum_widths)?;
            }
        }

        // If we failed to match, then we might not have any instructions. In that case, make sure
        // we still print the annotation.
        if self.instructions.is_empty() {
            write!(f, "{:name_width$} ", self.name.blue())?;

            self.write_annotation(f, 0)?;
            self.write_traces(f, maximum_widths)?;
        }

        for message in &self.trace.messages {
            writeln!(f, "{:name_width$} {message}", self.name.blue())?;
        }

        Ok(())
    }

    fn write_annotation(&self, f: &mut String, num_spaces: usize) -> Result {
        let Some(annotation) = self.annotation.as_ref() else {
            return Ok(());
        };

        match annotation {
            Annotation::Success(inner) => {
                inner.write_to(f, num_spaces)?;
            }
            Annotation::Ambiguous(possible) => {
                for a in possible {
                    a.write_to(f, num_spaces)?;
                    writeln!(f)?;
                }
            }
            Annotation::MatchFailed(failures) => {
                for m in failures {
                    write!(f, "{:num_spaces$}", "")?;
                    m.write_to(f)?;
                    writeln!(f)?;
                }
            }
            Annotation::LiteralByteMismatch => {
                return Ok(());
            }
        }

        writeln!(f)?;

        Ok(())
    }

    fn write_traces(&self, f: &mut String, maximum_widths: &ColumnWidths) -> Result {
        let name_width = maximum_widths.name;
        let prefix = " TRACE: ";
        let margin = name_width + prefix.len();
        const WRAP_COLUMN: usize = 80;

        for trace in &self.trace_messages {
            write!(f, "{:name_width$}{prefix}", self.name.blue())?;

            // Crude word wrapping should be sufficient for a trace message. TODO: Consider changing
            // our tracing code (in wild) to emit fields separated by newlines, then get rid of this
            // word wrapping and just indent the lines appropriately.
            let mut line_length = 0;
            for word in trace.split(' ') {
                if line_length > 0 && margin + line_length + word.len() > WRAP_COLUMN {
                    writeln!(f)?;
                    write!(f, "{:margin$}", "")?;
                    line_length = 0;
                }

                if line_length > 0 {
                    write!(f, " ")?;
                    line_length += 1;
                }

                write!(f, "{word}")?;
                line_length += word.len();
            }

            writeln!(f)?;
        }

        Ok(())
    }
}

impl<A: Arch> SuccessAnnotation<'_, A> {
    fn write_to(&self, f: &mut String, num_spaces: usize) -> Result {
        write!(f, "{:num_spaces$}", "")?;
        write_carets_for_r_type(f, self.r_type)?;
        write!(f, "{} ", self.r_type.to_string().green())?;
        if let Some(r) = self.relaxation_kind {
            write!(f, "{} ", format!("{r:?}").bright_green())?;
        }
        writeln!(f)?;

        let num_spaces = num_spaces + num_carets_for_r_type(self.r_type) + 1;
        write!(f, "{:num_spaces$}", "")?;
        self.reference.write_to(f)?;

        Ok(())
    }
}

fn write_carets_for_r_type<R: RType>(f: &mut String, r_type: R) -> Result {
    let num_carets = num_carets_for_r_type(r_type);
    write!(f, "{:^<num_carets$} ", "")?;
    Ok(())
}

fn num_carets_for_r_type<R: RType>(r_type: R) -> usize {
    let relocation_size = r_type.relocation_info().map_or(1, relocation_num_bytes);
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
struct Resolution<'data, A: Arch> {
    /// The chosen relaxation if we successfully matched to exactly one.
    relaxation: Option<Relaxation<A>>,

    annotation: Annotation<'data, A>,

    reference: Reference<'data, A::RType>,

    /// The inclusive start of the bytes associated with this resolution.
    start: u64,

    /// The exclusive end of the bytes associated with this resolution. This should the the offset
    /// of the first byte after the later of (a) any instructions modified by the relaxation and (b)
    /// the bytes of the relocation offset.
    end: u64,

    next_modifier: RelocationModifier,

    /// The offset at which the relocation would be applied.
    offset: u64,

    trace: TraceOutput,
}

impl<'data, A: Arch> Resolution<'data, A> {
    /// Multiple possible resolutions have been identified. Mark `self` as ambiguous and merge the
    /// supplied resolution into this one.
    fn merge_ambiguous(&mut self, other: Resolution<'data, A>) {
        let mut possible = match &mut self.annotation {
            Annotation::Success(success_annotation) => {
                vec![success_annotation.clone()]
            }
            Annotation::Ambiguous(possible) => core::mem::take(possible),
            Annotation::MatchFailed(_) => return,
            Annotation::LiteralByteMismatch => return,
        };

        match other.annotation {
            Annotation::Success(o) => possible.push(o),
            Annotation::Ambiguous(mut o) => possible.append(&mut o),
            Annotation::MatchFailed(vec) => self.annotation = Annotation::MatchFailed(vec),
            Annotation::LiteralByteMismatch => return,
        }

        self.annotation = Annotation::Ambiguous(possible);

        self.start = self.start.min(other.start);
        self.end = self.end.max(other.end);
    }

    /// Returns whether two resolutions from different objects files match. Like equality, but only
    /// looks at the parts of the resolution that are expected to match.
    fn matches(&self, other: &Resolution<A>) -> bool {
        self.relaxation == other.relaxation && self.reference.matches(other.reference)
    }
}

/// Information about a thing that we reference and how it was referenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reference<'data, R: RType> {
    referent: Referent<'data, R>,

    /// The parts of the reference that aren't the referent.
    props: ReferenceProperties,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ReferenceProperties {
    /// Whether the reference was made via the PLT.
    via_plt: bool,

    /// Whether the reference was made via the GOT.
    via_got: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Referent<'data, R: RType> {
    Unknown,

    /// We have a name for the thing we reference. Second value is an offset from that name in case
    /// we're not pointing directly to it.
    Named(SymbolName<'data>, i64),

    DynamicRelocation(DynamicRelocation<'data, R>),

    UnmatchedAddress(UnmatchedAddress),

    Absolute(u64),

    MergedString(MergedStringRef<'data>),

    /// A reference to an ifunc. TODO: Validate that we're pointing to the correct ifunc.
    IFunc,
    DtpMod,
    UncheckedTlsThing,
    TlsDescCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MergedStringRef<'data> {
    data: &'data [u8],

    /// An addend applied to the string after determining which string we're working with. Only
    /// present when our string reference is via a named symbol. For unnamed symbols (section
    /// references), the addend is assumed to be applied before determining which string we're
    /// referencing.
    addend: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct UnmatchedAddress {
    address: u64,
    reason: Option<&'static str>,
}

impl<R: RType> Reference<'_, R> {
    fn write_to(&self, f: &mut String) -> Result {
        if self.props.via_plt {
            write!(f, "PLT{}", arrow())?;
        }

        if self.props.via_got {
            write!(f, "GOT{}", arrow())?;
        }

        self.referent.write_to(f)?;

        Ok(())
    }

    fn matches(self, other: Reference<'_, R>) -> bool {
        self.props == other.props && self.referent.matches(other.referent)
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
            Referent::UnmatchedAddress(unmatched) => {
                unmatched.write_to(f)?;
            }
            Referent::Absolute(value) => {
                write!(f, "#0x{value:x}")?;
            }
            Referent::MergedString(merged) => {
                merged.write_to(f)?;
            }
            Referent::DynamicRelocation(dynamic_relocation) => dynamic_relocation.write_to(f)?,
            Referent::IFunc => write!(f, "IFunc")?,
            Referent::DtpMod => write!(f, "DtpMod")?,
            Referent::TlsDescCall => write!(f, "TlsDescCall")?,
            Referent::UncheckedTlsThing => write!(f, "UncheckedTlsThing")?,
        }

        Ok(())
    }

    fn matches(self, other: Referent<'_, R>) -> bool {
        match (self, other) {
            (Referent::UnmatchedAddress(_), Referent::UnmatchedAddress(_)) => {
                // We don't yet support matching things that don't have symbol names. So long as
                // both files don't have a name for something, we accept it.
                true
            }
            (Referent::DynamicRelocation(a), Referent::DynamicRelocation(b)) => a.matches(b),
            _ => self == other,
        }
    }

    fn is_symbol_with_name(&self, name: &[u8]) -> bool {
        match self {
            Self::Named(n, _) => n.bytes == name,
            _ => false,
        }
    }
}

impl MergedStringRef<'_> {
    fn write_to(&self, f: &mut String) -> Result {
        if let Ok(str) = core::str::from_utf8(self.data) {
            write!(f, "MergedString({str:?})")?;
        } else {
            write!(f, "MergedString(InvalidUtf8({:?}))", self.data)?;
        }

        if let Some(addend) = self.addend {
            write!(f, "{addend:+}")?;
        }

        Ok(())
    }
}

impl UnmatchedAddress {
    fn write_to(&self, f: &mut String) -> Result {
        write!(f, "0x{:x}", self.address)?;
        if let Some(reason) = self.reason {
            write!(f, " ({reason})")?;
        }

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
            out.r_type = R::from_dynamic_relocation_kind(DynamicRelocationKind::DynamicSymbol);
        }

        out
    }
}

impl<R: RType> DynamicRelocation<'_, R> {
    fn write_to(&self, f: &mut String) -> Result {
        write!(f, "{}{}{}", self.r_type, arrow(), self.symbol)?;
        if self.addend != 0 {
            write!(f, " {:+}", self.addend)?;
        }
        Ok(())
    }
}

fn arrow() -> ColoredString {
    "->".bright_yellow()
}

#[derive(Clone)]
struct RelaxationTester<'data> {
    /// The section data from the original input object.
    original_data: &'data [u8],

    section_address: u64,

    section_bytes: Option<&'data [u8]>,

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

/// The maximum number of bytes prior to a relocation offset that a relaxation might modify.
const MAX_RELAX_MODIFY_BEFORE: u64 = 4;

/// The maximum number of bytes after a relocation offset that a relaxation might modify.
const MAX_RELAX_MODIFY_AFTER: u64 = 19;

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
                section_bytes = read_bytes(bin.elf_file, section_address, section_len);

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
            previous_end: 0,
            next_modifier: RelocationModifier::Normal,
            bin,
            section_address,
        })
    }

    /// Checks if the bytes in `section_data` match what we'd expect if the candidate relocation
    /// were applied to `original_data`. If it does, returns the value of the symbol used when the
    /// post-relaxation relocation was applied.
    fn resolve<A: Arch>(
        &self,
        candidate: Relaxation<A>,
        rel: &object::Relocation,
        mut offset: u64,
        original_referent: Referent<A::RType>,
    ) -> Result<MatchResult<'data, A>> {
        // Relocations need to have been previously sorted by offset.
        assert!(
            offset >= self.previous_end,
            "Relocations out of order or overlap {offset} < {}",
            self.previous_end
        );

        let fail = |reason| Ok(MatchResult::Failed(FailedMatch::new(candidate, reason)));

        let relaxation_range = A::relaxation_byte_range(candidate);

        if offset < relaxation_range.offset_shift {
            // There aren't enough bytes prior to offset in this section for the relaxation to be
            // possible.
            return fail("Not enough bytes prior");
        }

        // If our output section has no data (e.g. BSS), then no relaxation can have been applied,
        // since there would be no place to write the byte changes. Also, BSS isn't executable.
        let section_data = self
            .section_bytes
            .context("Attempted to diff section without data")?;

        let mut scratch = [0_u8; (MAX_RELAX_MODIFY_BEFORE + MAX_RELAX_MODIFY_AFTER) as usize];
        let base_scratch_offset = relaxation_range.offset_shift;

        let copy_start = (offset - base_scratch_offset) as usize;
        let copy_end = copy_start + relaxation_range.num_bytes;

        if copy_end > self.original_data.len() {
            return fail("Not enough bytes after");
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
            return fail("Prior bytes didn't match");
        }

        let mut addend = rel.addend();

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
            return fail("Relaxation output didn't match");
        }

        // Based on the change in offset when we applied the relaxation, compute the relocation
        // offset.
        offset = copy_start as u64 + scratch_offset;

        let reference =
            match self.read_reference(candidate, addend, offset, section_data, original_referent) {
                Ok(v) => v,
                Err(error) => {
                    return Ok(MatchResult::Failed(FailedMatch::new(
                        candidate,
                        error.to_string(),
                    )))
                }
            };

        let relocation_info = candidate
            .new_r_type
            .relocation_info()
            .context("Unsupported relocation kind")?;

        let end = (offset + relocation_num_bytes(relocation_info) as u64).max(copy_end as u64);

        if rel.kind() == object::RelocationKind::PltRelative {
            // Some relaxations cannot be identified purely by the instruction bytes. For example
            // relaxing a PLT32 to a PC32, the instruction bytes are left the same. All that differs is
            // whether we now point to the PLT or not.

            match relocation_info.kind {
                RelocationKind::PltRelative | RelocationKind::PltRelGotBase => {
                    if !reference.props.via_plt {
                        return fail("PLT relocation with non-PLT address");
                    }
                }
                _ => {
                    if reference.props.via_plt {
                        return fail("Non-PLT relocation with PLT address");
                    }
                }
            }
        }

        Ok(MatchResult::Matched(Resolution {
            relaxation: Some(candidate),
            annotation: Annotation::Success(SuccessAnnotation {
                r_type: candidate.new_r_type,
                relaxation_kind: Some(candidate.relaxation_kind),
                reference,
            }),
            reference,
            start: copy_start as u64,
            end,
            offset,
            next_modifier,
            trace: TraceOutput::default(),
        }))
    }

    fn read_reference<A: Arch>(
        &self,
        candidate: Relaxation<A>,
        addend: i64,
        offset: u64,
        section_data: &[u8],
        original_referent: Referent<A::RType>,
    ) -> Result<Reference<'data, A::RType>> {
        let relocation_info = candidate
            .new_r_type
            .relocation_info()
            .context("Unsupported relocation kind")?;

        let value_bytes = section_data
            .get(offset as usize..)
            .context("Invalid relocation offset")?;

        let mut value = match relocation_num_bytes(relocation_info) {
            8 => u64::from_le_bytes(
                *value_bytes
                    .first_chunk::<8>()
                    .context("Invalid relocation offset")?,
            ),
            4 => u64::from(u32::from_le_bytes(
                *value_bytes
                    .first_chunk::<4>()
                    .context("Invalid relocation offset")?,
            )),
            0 => 0,
            other => bail!("Unsupported relocation size {other}"),
        };

        let mut relative_to = 0;

        // Whether the value should be considered a pointer. If it is, then we do things like check
        // to see if it's pointing to a PLT or GOT entry. If we tried to do that with things that
        // weren't pointers, then we might get false PLT/GOT matches.
        let mut is_pointer = true;

        let mut referent = None;

        match relocation_info.kind {
            RelocationKind::Relative => {
                relative_to = self.section_address + offset;
            }
            RelocationKind::PltRelative
            | RelocationKind::TlsGd
            | RelocationKind::TlsLd
            | RelocationKind::TlsDesc
            | RelocationKind::GotTpOff
            | RelocationKind::GotRelative => {
                relative_to = self.section_address + offset;
            }
            RelocationKind::SymRelGotBase
            | RelocationKind::GotRelGotBase
            | RelocationKind::TlsGdGotBase
            | RelocationKind::GotTpOffGotBase
            | RelocationKind::TlsLdGotBase
            | RelocationKind::TlsDescGotBase
            | RelocationKind::PltRelGotBase => {
                relative_to = self
                    .bin
                    .address_index
                    .got_base_address
                    .context("Missing GOT base address")?;
            }
            RelocationKind::Absolute
            | RelocationKind::Got
            | RelocationKind::TlsGdGot
            | RelocationKind::GotTpOffGot
            | RelocationKind::AbsoluteAArch64
            | RelocationKind::TlsDescGot
            | RelocationKind::TlsLdGot => {
                // This is an absolute address, no adjustment to value is necessary.
            }
            RelocationKind::DtpOff
            | RelocationKind::TpOff
            | RelocationKind::TpOffAArch64
            | RelocationKind::None => {
                is_pointer = false;
            }
            RelocationKind::TlsDescCall => {
                is_pointer = false;
                referent = Some(Referent::TlsDescCall);
            }
        }

        value = value.wrapping_add(relative_to);

        if relocation_num_bytes(relocation_info) == 4 {
            value = u64::from(value as u32);
        }

        if let Referent::MergedString(orig_merged) = original_referent {
            let string_address = if let Some(addend) = orig_merged.addend {
                (value as i64 - addend) as u64
            } else if relocation_info.kind == RelocationKind::Relative {
                // We'd like to add the offset from the relocation to the next instruction, however
                // we don't have that information without decoding instructions, so we use the size
                // of relocation in bytes, since for instructions that load the address of a string,
                // that should be the same. Note, we can't use the addend because the addend is
                // sometimes used to select which string in the string merge section we're pointing
                // at. If we subtracted the addend, then instead of pointing at the correct string,
                // we'd end up pointing to the start of the string-merge section.
                value + relocation_num_bytes(relocation_info) as u64
            } else {
                value
            };

            let bytes =
                read_bytes_starting_at(self.bin.elf_file, string_address).with_context(|| {
                    format!("Failed to read bytes starting at 0x{string_address:x}")
                })?;
            let null_offset = memchr::memchr(0, bytes).with_context(|| {
                format!(
                    "Missing null-terminator for merged string starting at 0x{string_address:x}"
                )
            })?;

            referent = Some(Referent::MergedString(MergedStringRef {
                data: &bytes[..null_offset],
                addend: None,
            }));
        }

        value = value.wrapping_sub(addend as u64);

        if relocation_num_bytes(relocation_info) == 4 {
            value = u64::from(value as u32);
        }

        let mut reference_props = ReferenceProperties::default();

        if is_pointer {
            if let Some(got_address) = self.bin.address_index.plt_to_got_address::<A>(value)? {
                reference_props.via_plt = true;

                if !self.bin.address_index.is_got_address(got_address) {
                    bail!(
                        "PLT entry at 0x{value:x} points to non-GOT address 0x{got_address:x} in {}",
                        self.bin.section_containing_address(got_address).unwrap_or("??")
                    );
                }

                value = got_address;
            }

            // Generally if we see a pointer to somewhere in the GOT we look to see what's at that
            // location in the GOT. However, for relocations that are used to obtain a pointer to
            // the base of the GOT, we don't want to do this.
            let allow_got_dereference =
                !original_referent.is_symbol_with_name(b"_GLOBAL_OFFSET_TABLE_");

            if allow_got_dereference && self.bin.address_index.is_got_address(value) {
                reference_props.via_got = true;

                let got_entry = self.bin.address_index.dereference_got_address(
                    value,
                    relocation_info.kind,
                    &self.bin.address_index,
                )?;

                match got_entry {
                    Referent::UnmatchedAddress(unmatched) => value = unmatched.address,
                    Referent::Absolute(absolute_value)
                        if !self.bin.address_index.is_relocatable =>
                    {
                        // Our binary is non-relocatable, so we can treat an absolute value like
                        // an address.
                        value = absolute_value;
                    }
                    other => {
                        referent = Some(other);
                    }
                }
            }
        }

        let referent = referent.unwrap_or_else(|| {
            let reason;

            if let Referent::Named(original_name, _) = original_referent {
                match self.bin.symbol_by_name(original_name.bytes, value) {
                    crate::NameLookupResult::Defined(elf_symbol) => {
                        let offset = value.wrapping_sub(elf_symbol.address()) as i64;

                        if let Ok(bytes) = elf_symbol.name_bytes() {
                            let symbol_name = SymbolName {
                                bytes,
                                version: None,
                            };

                            if offset.abs() <= 8 {
                                return Referent::Named(symbol_name, offset);
                            }

                            reason = Some("symbol is too far away");
                        } else {
                            reason = Some("Error reading symbol name");
                        }
                    }
                    crate::NameLookupResult::Undefined => {
                        reason = Some("symbol is undefined");
                    }
                    crate::NameLookupResult::Duplicate => {
                        reason = Some("symbol has multiple definitions");
                    }
                }
            } else {
                reason = Some("original symbol has no name");
            }

            Referent::UnmatchedAddress(UnmatchedAddress {
                address: value,
                reason,
            })
        });

        Ok(Reference {
            referent,
            props: reference_props,
        })
    }

    /// Try to resolve what happened with the supplied relocation at the offset. e.g. was the
    /// relocation applied as-is (a no-op relaxation), was some relaxation applied, or was the
    /// relocation skipped entirely due to the previous relocation.
    fn try_resolve<A: Arch>(
        &mut self,
        section_kind: SectionKind,
        offset: u64,
        rel: &object::Relocation,
        original_referent: Referent<A::RType>,
    ) -> Result<Option<Resolution<'data, A>>> {
        let r_type = get_r_type(rel);

        let mut selected_resolution: Option<Resolution<A>> = None;

        if self.next_modifier == RelocationModifier::SkipNextRelocation {
            // If one tester is skipping, then all should be, since otherwise the previous
            // relocation wouldn't have matched. So we don't need to do any comparison here and
            // can just skip the relocation.
            self.next_modifier = RelocationModifier::Normal;
            return Ok(None);
        }

        let mut error = None;

        A::possible_relaxations_do(r_type, section_kind, |relaxation| {
            match self.resolve(relaxation, rel, offset, original_referent) {
                Ok(MatchResult::Matched(resolution)) => {
                    if let Some(existing) = selected_resolution.as_mut() {
                        existing.merge_ambiguous(resolution);
                    } else {
                        selected_resolution = Some(resolution);
                    }
                }
                Ok(MatchResult::Failed(_)) => {}
                Err(e) => error = Some(e),
            }
        });

        if let Some(error) = error {
            return Err(error);
        }

        let res = match selected_resolution {
            Some(res) => res,
            None => {
                // We failed to match, try again, but this time collect up all of the failed matches
                // so that we can report them.
                let mut failed_matches = Vec::new();

                A::possible_relaxations_do(r_type, section_kind, |relaxation| {
                    let result = self.resolve(relaxation, rel, offset, original_referent);

                    match result {
                        Ok(MatchResult::Failed(failure)) => {
                            failed_matches.push(failure);
                        }
                        // We shouldn't really get here since we got no matches and no errors the
                        // first time.
                        Err(e) => panic!("Unexpected error: {e}"),
                        Ok(MatchResult::Matched(..)) => {
                            panic!("Unexpected match")
                        }
                    }
                });

                self.match_failed_placeholder(offset, r_type, failed_matches)
            }
        };

        self.accept(&res);

        Ok(Some(res))
    }

    fn accept<A: Arch>(&mut self, resolution: &Resolution<A>) {
        self.previous_end = resolution.end;
        self.next_modifier = resolution.next_modifier;
    }

    /// Returns whether section bytes are equal to the original input file from `self.previous_end`
    /// up to, but not including `offset`.
    fn is_equal_up_to(&self, offset: u64) -> bool {
        self.section_bytes.is_some_and(|b| {
            b[self.previous_end as usize..offset as usize]
                == self.original_data[self.previous_end as usize..offset as usize]
        })
    }

    /// Returns a placeholder resolution that we can use when we fail to identify a relocation at a
    /// particular offset.
    fn match_failed_placeholder<A: Arch>(
        &self,
        offset: u64,
        original_r_type: A::RType,
        failed_matches: Vec<FailedMatch<A>>,
    ) -> Resolution<'data, A> {
        let relocation_size = original_r_type
            .relocation_info()
            .map_or(1, relocation_num_bytes);

        Resolution {
            relaxation: None,
            annotation: Annotation::MatchFailed(failed_matches),
            reference: Reference {
                referent: Referent::Unknown,
                props: Default::default(),
            },
            start: self.previous_end,
            end: offset + relocation_size as u64,
            next_modifier: RelocationModifier::Normal,
            offset,
            trace: TraceOutput::default(),
        }
    }
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
            // 1:1 between output files. For now at least, we ignore non-text sections.
            if is_merge_section(&section)
                || section.size() == 0
                || section.kind() != SectionKind::Text
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SymbolName<'data> {
    bytes: &'data [u8],
    version: Option<&'data [u8]>,
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

    /// GOT addresses for each JMPREL relocation by their index.
    jmprel_got_addresses: Vec<u64>,

    /// The address of the start of the .got section.
    got_base_address: Option<u64>,

    /// Version names by their index.
    verneed: Vec<Option<&'data [u8]>>,

    /// Dynamic symbol names by their index.
    dynamic_symbol_names: Vec<SymbolName<'data>>,
    is_relocatable: bool,
    bin_attributes: BinAttributes,
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

        if self.entry_length != 0 && offset % self.entry_length != 0 {
            bail!(
                "PLT address 0x{plt_address:x} is not aligned to 0x{:x}",
                self.entry_length
            );
        }

        let plt_entry = if self.entry_length == 0 {
            // Sometimes linkers don't set the entry size on PLT sections. In that case, we try both
            // size 8 and if that fails, try size 16.
            self.decode_plt_entry_with_size::<A>(offset, 8)
                .or_else(|_| self.decode_plt_entry_with_size::<A>(offset, 16))?
        } else {
            self.decode_plt_entry_with_size::<A>(offset, self.entry_length)?
        };

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
    ) -> Result<PltEntry> {
        let entry_bytes = &self.bytes[offset as usize..(offset + entry_size) as usize];
        A::decode_plt_entry(entry_bytes, self.plt_base, offset)
            .context("Unrecognised PLT entry format")
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
            plt_indexes: Default::default(),
            got_tables: Default::default(),
            verneed: Default::default(),
            dynamic_symbol_names: Default::default(),
            jmprel_got_addresses: Vec::new(),
            dynamic_relocations_by_address: Default::default(),
            is_relocatable: is_relocatable(elf_file),
            bin_attributes: BinAttributes {
                // These may be overridden in `index_dynamic`.
                output_kind: OutputKind::Executable,
                relocatability: Relocatability::NonRelocatable,
                link_type: LinkType::Static,
            },
        };

        if let Err(error) = info.build_indexes(elf_file) {
            info.index_error = Some(error);
        }
        info
    }

    fn build_indexes(&mut self, elf_file: &ElfFile64<'data>) -> Result {
        self.index_dynamic(elf_file);
        self.verneed = Self::index_verneed(elf_file)?;
        self.dynamic_symbol_names = self.index_dynamic_symbols(elf_file)?;
        self.index_got_tables(elf_file).unwrap();
        self.index_relocations(elf_file);
        self.index_plt_sections(elf_file)?;
        Ok(())
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

    fn index_dynamic_symbols(&self, elf_file: &ElfFile64<'data>) -> Result<Vec<SymbolName<'data>>> {
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

            let version = version_index
                .and_then(|ver_index| self.verneed.get(ver_index as usize).copied().flatten())
                .or(match version_index {
                    Some(object::elf::VER_NDX_LOCAL) => Some(b"*local*"),
                    Some(object::elf::VER_NDX_GLOBAL) => Some(b"*global*"),
                    _ => None,
                });

            while dynamic_symbol_names.len() < sym_index {
                dynamic_symbol_names.push(SymbolName {
                    bytes: &[],
                    version: None,
                });
            }

            let name_bytes = sym.name_bytes()?;
            dynamic_symbol_names.push(SymbolName {
                bytes: name_bytes,
                version,
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
        let entry_size = size_of::<u64>();

        let raw_entries: &[u64] = object::slice_from_bytes(data, data.len() / entry_size)
            .unwrap()
            .0;

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

        if dynamic_segment.is_some() {
            // We'll change back to executable if the PIE flag is set below.
            self.bin_attributes.output_kind = OutputKind::SharedObject;
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

    fn dereference_got_address<R: RType>(
        &self,
        got_address: u64,
        relocation_kind: RelocationKind,
        index: &AddressIndex<'data>,
    ) -> Result<Referent<'data, R>> {
        let table = self
            .got_tables
            .iter()
            .find(|table| table.address_range.contains(&got_address))
            .context("Address isn't in any GOT tables")?;

        table.dereference_got_address(got_address, relocation_kind, index)
    }
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
        index: &AddressIndex<'data>,
    ) -> Result<Referent<'data, R>> {
        let offset = got_address
            .checked_sub(self.address_range.start)
            .context("got_address outside index range")?;

        let entry_size = size_of::<u64>() as u64;
        if offset % entry_size != 0 {
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
                        .dynamic_symbol_names
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
                DynamicRelocationKind::Irelative => Ok(Referent::IFunc),
                DynamicRelocationKind::DtpMod => Ok(Referent::DtpMod),
                DynamicRelocationKind::TpOff if symbol.is_none() => {
                    Ok(Referent::Absolute(rel.addend() as u64))
                }
                _ => {
                    let symbol = symbol.with_context(|| format!("{r_type} without symbol"))?;

                    Ok(Referent::DynamicRelocation(DynamicRelocation {
                        symbol: *symbol,
                        r_type,
                        addend: rel.addend(),
                    }))
                }
            }
        } else {
            // No dynamic relocation, just read from the original file data.
            let raw_value = self
                .entries
                .get((offset / entry_size) as usize)
                .context("got_address past end of index range")?;

            match relocation_kind {
                RelocationKind::TlsGd
                | RelocationKind::TlsGdGot
                | RelocationKind::TlsGdGotBase
                | RelocationKind::TlsLd
                | RelocationKind::TlsLdGot
                | RelocationKind::TlsLdGotBase
                | RelocationKind::DtpOff
                | RelocationKind::GotTpOff
                | RelocationKind::GotTpOffGot
                | RelocationKind::GotTpOffGotBase
                | RelocationKind::TpOff
                | RelocationKind::TpOffAArch64
                | RelocationKind::TlsDesc
                | RelocationKind::TlsDescGot
                | RelocationKind::TlsDescGotBase
                | RelocationKind::TlsDescCall => Ok(Referent::UncheckedTlsThing),
                _ => Ok(Referent::Absolute(*raw_value)),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DynamicRelocation<'data, R: RType> {
    symbol: SymbolName<'data>,
    r_type: R,
    addend: i64,
}

fn is_relocatable(elf_file: &ElfFile64) -> bool {
    elf_file.elf_header().e_type(LittleEndian) == object::elf::ET_DYN
}

/// Attempts to read some data starting at `address` up to the end of the segment.
fn read_segment<'data>(elf_file: &ElfFile64<'data>, address: u64) -> Option<Data<'data>> {
    // This could well end up needing to be optimised if we end up caring about performance.
    for raw_seg in elf_file.elf_program_headers() {
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
                return Some(Data::Bss);
            }
            let bytes = &file_bytes[file_start..file_end];
            return Some(Data::Bytes(&bytes[start..]));
        }
    }
    None
}

fn read_bytes<'data>(elf_file: &ElfFile64<'data>, address: u64, len: u64) -> Option<&'data [u8]> {
    read_segment(elf_file, address).and_then(|data| match data {
        Data::Bytes(bytes) => bytes.get(..len as usize),
        Data::Bss => None,
    })
}

/// Returns bytes starting at `address` up to the end of the containing segment. This is useful when
/// you don't know what length you need to read, e.g. when reading a null-terminated string.
fn read_bytes_starting_at<'data>(elf_file: &ElfFile64<'data>, address: u64) -> Option<&'data [u8]> {
    read_segment(elf_file, address).and_then(|data| match data {
        Data::Bytes(bytes) => Some(bytes),
        Data::Bss => None,
    })
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
        linker_utils::elf::RelocationSize::BitMasking { range, .. } => {
            (range.end.div_ceil(8) - range.start / 8) as usize
        }
    }
}
