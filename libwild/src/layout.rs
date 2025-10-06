//! Traverses the graph of symbol references to figure out what sections from the input files are
//! referenced. Determines which sections need to be linked, sums their sizes decides what goes
//! where in the output file then allocates addresses for each symbol.

use self::elf::GNU_NOTE_NAME;
use self::elf::GNU_NOTE_PROPERTY_ENTRY_SIZE;
use self::elf::NoteHeader;
use self::elf::Symbol;
use self::output_section_id::InfoInputs;
use crate::alignment;
use crate::alignment::Alignment;
use crate::arch::Arch;
use crate::arch::Relaxation as _;
use crate::args::Args;
use crate::args::BuildIdOption;
use crate::args::OutputKind;
use crate::bail;
use crate::debug_assert_bail;
use crate::diagnostics::SymbolInfoPrinter;
use crate::elf;
use crate::elf::DynamicRelocationSequence;
use crate::elf::EhFrameHdrEntry;
use crate::elf::File;
use crate::elf::FileHeader;
use crate::elf::RelocationList;
use crate::elf::RelocationSequence;
use crate::elf::Versym;
use crate::elf_writer;
use crate::ensure;
use crate::error;
use crate::error::Context;
use crate::error::Error;
use crate::error::Result;
use crate::error::warning;
use crate::file_writer;
use crate::grouping::Group;
use crate::input_data::FileId;
use crate::input_data::InputData;
use crate::input_data::InputRef;
use crate::input_data::PRELUDE_FILE_ID;
use crate::layout_rules::SectionKind;
use crate::output_section_id;
use crate::output_section_id::FILE_HEADER;
use crate::output_section_id::OrderEvent;
use crate::output_section_id::OutputOrder;
use crate::output_section_id::OutputSectionId;
use crate::output_section_id::OutputSections;
use crate::output_section_map::OutputSectionMap;
use crate::output_section_part_map::OutputSectionPartMap;
use crate::parsing::InternalSymDefInfo;
use crate::parsing::SymbolPlacement;
use crate::part_id;
use crate::part_id::NUM_SINGLE_PART_SECTIONS;
use crate::part_id::PartId;
use crate::program_segments::ProgramSegmentId;
use crate::program_segments::ProgramSegments;
use crate::resolution;
use crate::resolution::FrameIndex;
use crate::resolution::NotLoaded;
use crate::resolution::ResolutionOutputs;
use crate::resolution::ResolvedEpilogue;
use crate::resolution::ResolvedLinkerScript;
use crate::resolution::SectionSlot;
use crate::resolution::UnloadedSection;
use crate::resolution::ValueFlags;
use crate::sharding::ShardKey;
use crate::string_merging::MergedStringStartAddresses;
use crate::string_merging::MergedStringsSection;
use crate::string_merging::get_merged_string_output_address;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::RawSymbolName;
use crate::symbol_db::SymbolDb;
use crate::symbol_db::SymbolDebug;
use crate::symbol_db::SymbolId;
use crate::symbol_db::SymbolIdRange;
use crate::symbol_db::is_mapping_symbol_name;
use bitflags::bitflags;
use crossbeam_queue::ArrayQueue;
use crossbeam_queue::SegQueue;
use hashbrown::HashMap;
use indexmap::IndexMap;
use itertools::Itertools;
use linker_utils::elf::RISCV_ATTRIBUTE_VENDOR_NAME;
use linker_utils::elf::RelocationKind;
use linker_utils::elf::SectionFlags;
use linker_utils::elf::SectionType;
use linker_utils::elf::pt;
use linker_utils::elf::riscvattr::TAG_RISCV_ARCH;
use linker_utils::elf::riscvattr::TAG_RISCV_ATOMIC_ABI;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_MINOR;
use linker_utils::elf::riscvattr::TAG_RISCV_PRIV_SPEC_REVISION;
use linker_utils::elf::riscvattr::TAG_RISCV_STACK_ALIGN;
use linker_utils::elf::riscvattr::TAG_RISCV_UNALIGNED_ACCESS;
use linker_utils::elf::riscvattr::TAG_RISCV_WHOLE_FILE;
use linker_utils::elf::riscvattr::TAG_RISCV_X3_REG_USAGE;
use linker_utils::elf::secnames;
use linker_utils::elf::shf;
use linker_utils::elf::sht;
use linker_utils::relaxation::RelocationModifier;
use object::LittleEndian;
use object::SectionIndex;
use object::elf::gnu_hash;
use object::read::elf::Crel;
use object::read::elf::Dyn as _;
use object::read::elf::RelocationSections;
use object::read::elf::SectionHeader as _;
use object::read::elf::Sym;
use object::read::elf::VerdefIterator;
use rayon::iter::IndexedParallelIterator;
use rayon::iter::IntoParallelIterator;
use rayon::iter::IntoParallelRefMutIterator;
use rayon::iter::ParallelIterator;
use rayon::slice::ParallelSliceMut;
use smallvec::SmallVec;
use std::ffi::CStr;
use std::ffi::CString;
use std::fmt::Display;
use std::io::Cursor;
use std::mem::replace;
use std::mem::size_of;
use std::mem::swap;
use std::mem::take;
use std::num::NonZeroU32;
use std::num::NonZeroU64;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::AtomicU64;

#[tracing::instrument(skip_all, name = "Layout")]
pub fn compute<'data, A: Arch>(
    symbol_db: SymbolDb<'data>,
    resolved: ResolutionOutputs<'data>,
    mut output_sections: OutputSections<'data>,
    output: &mut file_writer::Output,
    input_data: &InputData<'data>,
) -> Result<Layout<'data>> {
    let ResolutionOutputs {
        groups,
        merged_strings,
    } = resolved;

    let symbol_resolution_flags = vec![AtomicResolutionFlags::empty(); symbol_db.num_symbols()];

    let symbol_info_printer = symbol_db.args.sym_info.as_ref().map(|sym_name| {
        SymbolInfoPrinter::new(&symbol_db, sym_name, &symbol_resolution_flags, &groups)
    });

    let gc_outputs = find_required_sections::<A>(
        groups,
        &symbol_db,
        &output_sections,
        &symbol_resolution_flags,
        &merged_strings,
        input_data,
    )?;

    let mut group_states = gc_outputs.group_states;

    finalise_copy_relocations(&mut group_states, &symbol_db, &symbol_resolution_flags)?;
    merge_dynamic_symbol_definitions(&mut group_states)?;
    merge_gnu_property_notes::<A>(&mut group_states)?;
    merge_eflags::<A>(&mut group_states)?;
    merge_riscv_attributes::<A>(&mut group_states)?;

    finalise_all_sizes(
        &symbol_db,
        &output_sections,
        &mut group_states,
        &symbol_resolution_flags,
    )?;

    // Dropping `symbol_info_printer` will cause it to print. So we'll either print now, or, if we
    // got an error, then we'll have printed at that point.
    drop(symbol_info_printer);

    let mut symbol_resolution_flags: Vec<ResolutionFlags> = symbol_resolution_flags
        .into_iter()
        .map(|f| f.into_non_atomic())
        .collect();

    let non_addressable_counts = apply_non_addressable_indexes(&mut group_states, &symbol_db)?;

    propagate_section_attributes(&group_states, &mut output_sections);

    let (output_order, program_segments) = output_sections.output_order();

    tracing::trace!(
        "Output order:\n{}",
        output_order.display(&output_sections, &program_segments)
    );

    let section_part_sizes = compute_total_section_part_sizes(
        &mut group_states,
        &mut output_sections,
        &output_order,
        &program_segments,
        &mut symbol_resolution_flags,
        gc_outputs.sections_with_content,
        &symbol_db,
    )?;

    let section_part_layouts = layout_section_parts(
        &section_part_sizes,
        &output_sections,
        &program_segments,
        &output_order,
        symbol_db.args,
    );
    let section_layouts = layout_sections(&output_sections, &section_part_layouts);
    output.set_size(compute_total_file_size(&section_layouts));

    let Some(FileLayoutState::Prelude(internal)) =
        &group_states.first().and_then(|g| g.files.first())
    else {
        unreachable!();
    };
    let header_info = internal.header_info.as_ref().unwrap();
    let segment_layouts = compute_segment_layout(
        &section_layouts,
        &output_sections,
        &output_order,
        &program_segments,
        header_info,
    )?;

    let mem_offsets: OutputSectionPartMap<u64> = starting_memory_offsets(&section_part_layouts);
    let starting_mem_offsets_by_group = compute_start_offsets_by_group(&group_states, mem_offsets);

    let merged_string_start_addresses = MergedStringStartAddresses::compute(
        &output_sections,
        &starting_mem_offsets_by_group,
        &merged_strings,
    );

    let mut symbol_resolutions = SymbolResolutions {
        resolutions: Vec::with_capacity(symbol_db.num_symbols()),
    };

    let mut res_writer = sharded_vec_writer::VecWriter::new(&mut symbol_resolutions.resolutions);

    let mut per_group_res_writers = group_states
        .iter()
        .map(|group| res_writer.take_shard(group.num_symbols))
        .collect_vec();

    let resources = FinaliseLayoutResources {
        symbol_db: &symbol_db,
        symbol_resolution_flags: &symbol_resolution_flags,
        output_sections: &output_sections,
        output_order: &output_order,
        section_layouts: &section_layouts,
        merged_string_start_addresses: &merged_string_start_addresses,
        merged_strings: &merged_strings,
    };

    let group_layouts = compute_symbols_and_layouts(
        group_states,
        starting_mem_offsets_by_group,
        &mut per_group_res_writers,
        &resources,
    )?;

    for shard in per_group_res_writers {
        res_writer
            .try_return_shard(shard)
            .context("Group resolutions not filled")?;
    }

    update_dynamic_symbol_resolutions(&group_layouts, &mut symbol_resolutions.resolutions);
    crate::gc_stats::maybe_write_gc_stats(&group_layouts, symbol_db.args)?;

    let relocation_statistics = OutputSectionMap::with_size(section_layouts.len());

    Ok(Layout {
        symbol_db,
        symbol_resolutions,
        segment_layouts,
        section_part_layouts,
        section_layouts,
        group_layouts,
        output_sections,
        program_segments,
        output_order,
        non_addressable_counts,
        symbol_resolution_flags,
        merged_strings,
        merged_string_start_addresses,
        has_static_tls: gc_outputs.has_static_tls,
        relocation_statistics,
    })
}

/// Update resolutions for all dynamic symbols that our output file defines.
#[tracing::instrument(skip_all, name = "Update dynamic symbol resolutions")]
fn update_dynamic_symbol_resolutions(
    layouts: &[GroupLayout],
    resolutions: &mut [Option<Resolution>],
) {
    let Some(FileLayout::Epilogue(epilogue)) = layouts.last().and_then(|g| g.files.last()) else {
        panic!("Epilogue should be the last file");
    };

    for (index, sym) in epilogue.dynamic_symbol_definitions.iter().enumerate() {
        let dynamic_symbol_index = NonZeroU32::try_from(epilogue.dynsym_start_index + index as u32)
            .expect("Dynamic symbol definitions should start > 0");
        if let Some(res) = &mut resolutions[sym.symbol_id.as_usize()] {
            res.dynamic_symbol_index = Some(dynamic_symbol_index);
        }
    }
}

/// Where we've decided that we need copy relocations, look for symbols with the same address as the
/// symbols with copy relocations. If the other symbol is non-weak, then we do the copy relocation
/// for that symbol instead. We also request dynamic symbol definitions for each copy relocation.
/// For that reason, this needs to be done before we merge dynamic symbol definitions.
#[tracing::instrument(skip_all, name = "Finalise copy relocations")]
fn finalise_copy_relocations<'data>(
    group_states: &mut [GroupState<'data>],
    symbol_db: &SymbolDb<'data>,
    symbol_resolution_flags: &[AtomicResolutionFlags],
) -> Result {
    group_states.par_iter_mut().try_for_each(|group| {
        for file in &mut group.files {
            if let FileLayoutState::Dynamic(dynamic) = file {
                dynamic.finalise_copy_relocations(
                    &mut group.common,
                    symbol_db,
                    symbol_resolution_flags,
                )?;
            }
        }

        Ok(())
    })
}

#[tracing::instrument(skip_all, name = "Finalise per-object sizes")]
fn finalise_all_sizes<'data>(
    symbol_db: &SymbolDb<'data>,
    output_sections: &OutputSections,
    group_states: &mut [GroupState<'data>],
    symbol_resolution_flags: &[AtomicResolutionFlags],
) -> Result {
    group_states.par_iter_mut().try_for_each(|state| {
        state.finalise_sizes(symbol_db, output_sections, symbol_resolution_flags)
    })
}

fn get_prelude_mut<'a, 'data>(
    group_states: &'a mut [GroupState<'data>],
) -> &'a mut PreludeLayoutState<'data> {
    let Some(FileLayoutState::Prelude(prelude)) =
        group_states.first_mut().and_then(|g| g.files.first_mut())
    else {
        panic!("Internal error, prelude must be first");
    };
    prelude
}

fn get_epilogue_mut<'a, 'data>(
    group_states: &'a mut [GroupState<'data>],
) -> &'a mut EpilogueLayoutState<'data> {
    let Some(FileLayoutState::Epilogue(epilogue)) =
        group_states.last_mut().and_then(|g| g.files.last_mut())
    else {
        panic!("Internal error, epilogue must be last");
    };
    epilogue
}

#[tracing::instrument(skip_all, name = "Merge dynamic symbol definitions")]
fn merge_dynamic_symbol_definitions(group_states: &mut [GroupState]) -> Result {
    let mut dynamic_symbol_definitions = Vec::new();
    for group in group_states.iter() {
        dynamic_symbol_definitions.extend(group.common.dynamic_symbol_definitions.iter().copied());
    }

    let epilogue = get_epilogue_mut(group_states);
    epilogue.dynamic_symbol_definitions = dynamic_symbol_definitions;
    Ok(())
}

pub(crate) enum PropertyClass {
    // A bit in the output pr_data is set if it is set in any relocatable input.
    // If all bits in the output pr_data field are zero, this property should be removed from output.
    Or,
    // A bit in the output pr_data field is set only if it is set in all relocatable input pr_data fields.
    // If all bits in the output pr_data field are zero, this property should be removed from output.
    And,
    // A bit in the output pr_data field is set if it is set in any relocatable input pr_data fields
    // and this property is present in all relocatable input files. When all bits in the output pr_data
    // field are zero, this property should not be removed from output to indicate it has
    // zero in all bits.
    AndOr,
}

#[tracing::instrument(skip_all, name = "Merge GNU property notes")]
fn merge_gnu_property_notes<A: Arch>(group_states: &mut [GroupState]) -> Result {
    let properties_per_file = group_states
        .iter()
        .flat_map(|group| {
            group.files.iter().filter_map(|file| {
                if let FileLayoutState::Object(object) = file {
                    Some(&object.gnu_property_notes)
                } else {
                    None
                }
            })
        })
        .collect_vec();

    // Merge bits of each property type based on type: OR or AND operation.
    let mut property_map = HashMap::new();

    for file_props in &properties_per_file {
        for prop in *file_props {
            let property_class = A::get_property_class(prop.ptype)
                .ok_or_else(|| crate::error!("unclassified property type {}", prop.ptype))?;
            property_map
                .entry(prop.ptype)
                .and_modify(|entry: &mut (u32, PropertyClass)| {
                    if matches!(property_class, PropertyClass::And) {
                        entry.0 &= prop.data;
                    } else {
                        entry.0 |= prop.data;
                    }
                })
                .or_insert_with(|| (prop.data, property_class));
        }
    }

    // Iterate the properties sorted by property_type so that we have a stable output!
    let output_properties = property_map
        .into_iter()
        .sorted_by_key(|x| x.0)
        .filter_map(|(property_type, (property_value, property_class))| {
            let type_present_in_all = properties_per_file.iter().all(|props_per_file| {
                props_per_file
                    .iter()
                    .any(|prop| prop.ptype == property_type)
            });
            if match property_class {
                PropertyClass::Or => property_value != 0,
                PropertyClass::And => type_present_in_all && property_value != 0,
                PropertyClass::AndOr => type_present_in_all,
            } {
                Some(GnuProperty {
                    ptype: property_type,
                    data: property_value,
                })
            } else {
                None
            }
        })
        .collect_vec();

    let epilogue = get_epilogue_mut(group_states);
    epilogue.gnu_property_notes = output_properties;
    Ok(())
}

#[tracing::instrument(skip_all, name = "Merge e_flags")]
fn merge_eflags<A: Arch>(group_states: &mut [GroupState]) -> Result {
    let eflags = group_states
        .iter()
        .flat_map(|group| {
            group.files.iter().filter_map(|file| {
                if let FileLayoutState::Object(object) = file {
                    Some(object.object.eflags)
                } else {
                    None
                }
            })
        })
        .collect_vec();

    let prelude = get_prelude_mut(group_states);
    prelude.eflags = A::merge_eflags(&eflags)?;
    Ok(())
}

#[tracing::instrument(skip_all, name = "Merge .riscv.attributes sections")]
fn merge_riscv_attributes<A: Arch>(group_states: &mut [GroupState]) -> Result {
    let attributes = group_states
        .iter()
        .flat_map(|group| {
            group.files.iter().filter_map(|file| {
                if let FileLayoutState::Object(object) = file {
                    Some(&object.riscv_attributes)
                } else {
                    None
                }
            })
        })
        // Sort by the number of ISAs: better output ordering
        .sorted_by_key(|x| x.len())
        .rev()
        .flatten()
        .collect_vec();

    let mut merged = Vec::new();

    let mut arch_components = IndexMap::new();
    for (name, version) in attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::Arch(arch) = a {
                Some(&arch.map)
            } else {
                None
            }
        })
        .flatten()
    {
        // Right now, we merge all the ISA extensions and use the maximum version.
        // TODO: Add more verifier that rejects invalid combination of extensions.
        arch_components
            .entry(name.clone())
            .and_modify(|v: &mut (u64, u64)| *v = (*v).max(*version))
            .or_insert(*version);
    }
    if !arch_components.is_empty() {
        merged.push(RiscVAttribute::Arch(RiscVArch {
            map: arch_components,
        }));
    }

    if let Some(align) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::StackAlign(align) = a {
                Some(align)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::StackAlign(*align));
    }
    if let Some(access) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::UnalignedAccess(access) = a {
                Some(access)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::UnalignedAccess(*access));
    }
    if let Some(version) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::PrivilegedSpecMajor(version) = a {
                Some(version)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::PrivilegedSpecMajor(*version));
    }
    if let Some(version) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::PrivilegedSpecMinor(version) = a {
                Some(version)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::PrivilegedSpecMinor(*version));
    }
    if let Some(version) = attributes
        .iter()
        .filter_map(|a| {
            if let RiscVAttribute::PrivilegedSpecRevision(version) = a {
                Some(version)
            } else {
                None
            }
        })
        .max()
    {
        merged.push(RiscVAttribute::PrivilegedSpecRevision(*version));
    }

    let epilogue = get_epilogue_mut(group_states);
    epilogue.riscv_attributes = merged;

    Ok(())
}

fn compute_total_file_size(section_layouts: &OutputSectionMap<OutputRecordLayout>) -> u64 {
    let mut file_size = 0;
    section_layouts.for_each(|_, s| file_size = file_size.max(s.file_offset + s.file_size));
    file_size as u64
}

/// Information about what goes where. Also includes relocation data, since that's computed at the
/// same time.
pub struct Layout<'data> {
    pub(crate) symbol_db: SymbolDb<'data>,
    pub(crate) symbol_resolutions: SymbolResolutions,
    pub(crate) section_part_layouts: OutputSectionPartMap<OutputRecordLayout>,
    pub(crate) section_layouts: OutputSectionMap<OutputRecordLayout>,
    pub(crate) group_layouts: Vec<GroupLayout<'data>>,
    pub(crate) segment_layouts: SegmentLayouts,
    pub(crate) output_sections: OutputSections<'data>,
    pub(crate) program_segments: ProgramSegments,
    pub(crate) output_order: OutputOrder,
    pub(crate) non_addressable_counts: NonAddressableCounts,
    pub(crate) symbol_resolution_flags: Vec<ResolutionFlags>,
    pub(crate) merged_strings: OutputSectionMap<MergedStringsSection<'data>>,
    pub(crate) merged_string_start_addresses: MergedStringStartAddresses,
    pub(crate) relocation_statistics: OutputSectionMap<AtomicU64>,
    pub(crate) has_static_tls: bool,
}

pub(crate) struct SegmentLayouts {
    /// The layout of each of our segments. Segments containing no active output sections will have
    /// been filtered, so don't try to index this by our internal segment IDs.
    pub(crate) segments: Vec<SegmentLayout>,
    pub(crate) tls_layout: Option<OutputRecordLayout>,
}

#[derive(Default, Clone)]
pub(crate) struct SegmentLayout {
    pub(crate) id: ProgramSegmentId,
    pub(crate) sizes: OutputRecordLayout,
}

pub(crate) struct SymbolResolutions {
    resolutions: Vec<Option<Resolution>>,
}

pub(crate) enum FileLayout<'data> {
    Prelude(PreludeLayout<'data>),
    Object(ObjectLayout<'data>),
    Dynamic(DynamicLayout<'data>),
    Epilogue(EpilogueLayout<'data>),
    NotLoaded,
    LinkerScript(LinkerScriptLayoutState<'data>),
}

/// Address information for a symbol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Resolution {
    /// An address or absolute value.
    pub(crate) raw_value: u64,

    pub(crate) dynamic_symbol_index: Option<NonZeroU32>,

    /// The base GOT address for this resolution. For pointers to symbols the GOT entry will contain
    /// a single pointer. For TLS variables there can be up to 3 pointers. If
    /// ResolutionFlags::GOT_TLS_OFFSET is set, then that will be the first value. If
    /// ResolutionFlags::GOT_TLS_MODULE is set, then there will be a pair of values (module and
    /// offset within module).
    pub(crate) got_address: Option<NonZeroU64>,
    pub(crate) plt_address: Option<NonZeroU64>,
    pub(crate) resolution_flags: ResolutionFlags,
    pub(crate) value_flags: ValueFlags,
}

/// Address information for a section.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SectionResolution {
    address: u64,
}

impl SectionResolution {
    /// Returns a resolution for a section that we didn't load, or for which we don't have an
    /// address (e.g. string-merge sections).
    fn none() -> SectionResolution {
        SectionResolution { address: u64::MAX }
    }

    pub(crate) fn address(self) -> Option<u64> {
        if self.address == u64::MAX {
            None
        } else {
            Some(self.address)
        }
    }

    /// Converts to a resolution compatible with what's used for symbols.
    pub(crate) fn full_resolution(self) -> Option<Resolution> {
        let address = self.address()?;
        Some(Resolution {
            raw_value: address,
            dynamic_symbol_index: None,
            got_address: None,
            plt_address: None,
            resolution_flags: ResolutionFlags::empty(),
            value_flags: ValueFlags::empty(),
        })
    }
}

enum FileLayoutState<'data> {
    Prelude(PreludeLayoutState<'data>),
    Object(ObjectLayoutState<'data>),
    Dynamic(DynamicLayoutState<'data>),
    NotLoaded(NotLoaded),
    Epilogue(EpilogueLayoutState<'data>),
    LinkerScript(LinkerScriptLayoutState<'data>),
}

/// Data that doesn't come from any input files, but needs to be written by the linker.
struct PreludeLayoutState<'data> {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols<'data>,
    entry_symbol_id: Option<SymbolId>,
    needs_tlsld_got_entry: bool,
    identity: String,
    header_info: Option<HeaderInfo>,
    dynamic_linker: Option<CString>,
    shstrtab_size: u64,
    eflags: u32,
}

pub(crate) struct EpilogueLayoutState<'data> {
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    internal_symbols: InternalSymbols<'data>,

    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
    gnu_hash_layout: Option<GnuHashLayout>,
    gnu_property_notes: Vec<GnuProperty>,
    build_id_size: Option<usize>,
    riscv_attributes: Vec<RiscVAttribute>,

    verdefs: Option<Vec<VersionDef>>,
}

pub(crate) struct LinkerScriptLayoutState<'data> {
    file_id: FileId,
    input: InputRef<'data>,
    symbol_id_range: SymbolIdRange,
    pub(crate) internal_symbols: InternalSymbols<'data>,
}

#[derive(Default, Debug)]
pub(crate) struct GnuHashLayout {
    pub(crate) bucket_count: u32,
    pub(crate) bloom_shift: u32,
    pub(crate) bloom_count: u32,
    pub(crate) symbol_base: u32,
}

pub(crate) struct EpilogueLayout<'data> {
    pub(crate) internal_symbols: InternalSymbols<'data>,
    pub(crate) gnu_hash_layout: Option<GnuHashLayout>,
    pub(crate) dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
    dynsym_start_index: u32,
    pub(crate) gnu_property_notes: Vec<GnuProperty>,
    pub(crate) verdefs: Option<Vec<VersionDef>>,
    pub(crate) riscv_attributes: Vec<RiscVAttribute>,
    pub(crate) riscv_attributes_length: u32,
}

pub(crate) struct ObjectLayout<'data> {
    pub(crate) input: InputRef<'data>,
    pub(crate) file_id: FileId,
    pub(crate) object: &'data File<'data>,
    pub(crate) sections: Vec<SectionSlot>,
    pub(crate) relocations: RelocationSections,
    pub(crate) section_resolutions: Vec<SectionResolution>,
    pub(crate) symbol_id_range: SymbolIdRange,
}

pub(crate) struct PreludeLayout<'data> {
    pub(crate) entry_symbol_id: Option<SymbolId>,
    pub(crate) tlsld_got_entry: Option<NonZeroU64>,
    pub(crate) identity: String,
    pub(crate) header_info: HeaderInfo,
    pub(crate) internal_symbols: InternalSymbols<'data>,
    pub(crate) dynamic_linker: Option<CString>,
}

pub(crate) struct InternalSymbols<'data> {
    pub(crate) symbol_definitions: Vec<InternalSymDefInfo<'data>>,
    pub(crate) start_symbol_id: SymbolId,
}

pub(crate) struct DynamicLayout<'data> {
    pub(crate) file_id: FileId,
    input: InputRef<'data>,

    /// The name we'll put into the binary to tell the dynamic loader what to load.
    pub(crate) lib_name: &'data [u8],

    pub(crate) symbol_id_range: SymbolIdRange,

    pub(crate) object: &'data crate::elf::File<'data>,

    /// Mapping from local symbol indexes to versions in the input file.
    pub(crate) input_symbol_versions: &'data [Versym],

    /// Mapping from input versions to output versions. Input version 1 is at index 0.
    pub(crate) version_mapping: Vec<u16>,

    pub(crate) verneed_info: Option<VerneedInfo<'data>>,

    /// Whether this is the last DynamicLayout that puts content into .gnu.version_r.
    pub(crate) is_last_verneed: bool,

    pub(crate) copy_relocation_symbols: Vec<SymbolId>,
}

trait HandlerData {
    fn symbol_id_range(&self) -> SymbolIdRange;

    fn file_id(&self) -> FileId;
}

trait SymbolRequestHandler<'data>: std::fmt::Display + HandlerData {
    fn finalise_symbol_sizes(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        let _file_span = symbol_db.args.trace_span_for_file(self.file_id());
        let symbol_id_range = self.symbol_id_range();

        for (local_index, resolution_flags) in symbol_resolution_flags[symbol_id_range.as_usize()]
            .iter()
            .enumerate()
        {
            let symbol_id = symbol_id_range.offset_to_id(local_index);
            if !symbol_db.is_canonical(symbol_id) {
                continue;
            }
            let value_flags = symbol_db.local_symbol_value_flags(symbol_id);
            let current_res_flags = resolution_flags.get();

            // It might be tempting to think that this code should only be run for dynamic objects,
            // however regular objects can own dynamic symbols too if the symbol is an undefined
            // weak symbol.
            if value_flags.is_dynamic() && !current_res_flags.is_empty() {
                let name = symbol_db.symbol_name(symbol_id)?;
                let name = RawSymbolName::parse(name.bytes()).name;

                if current_res_flags.needs_copy_relocation() {
                    // The dynamic symbol is a definition, so is handled by the epilogue. We only
                    // need to deal with the symtab entry here.
                    let entry_size = size_of::<elf::SymtabEntry>() as u64;
                    common.allocate(part_id::SYMTAB_GLOBAL, entry_size);
                    common.allocate(part_id::STRTAB, name.len() as u64 + 1);
                } else {
                    common.allocate(part_id::DYNSTR, name.len() as u64 + 1);
                    common.allocate(part_id::DYNSYM, crate::elf::SYMTAB_ENTRY_SIZE);
                }
            }

            if symbol_db.args.verify_allocation_consistency {
                verify_consistent_allocation_handling(
                    value_flags,
                    resolution_flags.get(),
                    symbol_db.args.output_kind(),
                )?;
            }

            allocate_symbol_resolution(
                value_flags,
                resolution_flags,
                &mut common.mem_sizes,
                symbol_db.args.output_kind(),
            );

            if symbol_db.args.got_plt_syms && resolution_flags.get().needs_got() {
                let name = symbol_db.symbol_name(symbol_id)?;
                let name = RawSymbolName::parse(name.bytes()).name;
                let name_len = name.len() + 4; // "$got" or "$plt" suffix

                let entry_size = size_of::<elf::SymtabEntry>() as u64;
                common.allocate(part_id::SYMTAB_LOCAL, entry_size);
                common.allocate(part_id::STRTAB, name_len as u64 + 1);
                if resolution_flags.get().needs_plt() {
                    common.allocate(part_id::SYMTAB_LOCAL, entry_size);
                    common.allocate(part_id::STRTAB, name_len as u64 + 1);
                }
            }
        }
        if symbol_db.args.should_output_symbol_versions() {
            let num_dynamic_symbols =
                common.mem_sizes.get(part_id::DYNSYM) / crate::elf::SYMTAB_ENTRY_SIZE;
            // Note, sets the GNU_VERSION allocation rather than incrementing it. Assuming there are
            // multiple files in our group, we'll update this same value multiple times, each time
            // with a possibly revised dynamic symbol count. The important thing is that when we're
            // done finalising the group sizes, the GNU_VERSION size should be consistent with the
            // DYNSYM size.
            *common.mem_sizes.get_mut(part_id::GNU_VERSION) =
                num_dynamic_symbols * crate::elf::GNU_VERSION_ENTRY_SIZE;
        }
        Ok(())
    }

    fn load_symbol<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result;
}

fn export_dynamic<'data>(
    common: &mut CommonGroupState<'data>,
    symbol_id: SymbolId,
    symbol_db: &SymbolDb<'data>,
) -> Result {
    let name = symbol_db.symbol_name(symbol_id)?;
    let RawSymbolName {
        name,
        version_name,
        is_default,
    } = RawSymbolName::parse(name.bytes());

    let mut version = object::elf::VER_NDX_GLOBAL;
    if symbol_db.version_script.version_count() > 0 {
        // TODO: We already hashed this symbol at some point previously. See if we can avoid
        // rehashing it here and if that actually saves us time.
        if let Some(v) = symbol_db
            .version_script
            .version_for_symbol(&UnversionedSymbolName::prehashed(name), version_name)?
        {
            version = v;
            if !is_default {
                version |= object::elf::VERSYM_HIDDEN;
            }
        }
    }

    common
        .dynamic_symbol_definitions
        .push(DynamicSymbolDefinition::new(symbol_id, name, version));

    Ok(())
}

fn allocate_symbol_resolution(
    value_flags: ValueFlags,
    resolution_flags: &AtomicResolutionFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    let mut r = resolution_flags.get();
    if !r.is_empty() && value_flags.is_ifunc() {
        resolution_flags.fetch_or(ResolutionFlags::GOT | ResolutionFlags::PLT);
        r |= ResolutionFlags::GOT | ResolutionFlags::PLT;
    }

    allocate_resolution(value_flags, r, mem_sizes, output_kind);
}

/// Computes how much to allocate for a particular resolution. This is intended for debug assertions
/// when we're writing, to make sure that we would have allocated memory before we write.
pub(crate) fn compute_allocations(
    resolution: &Resolution,
    output_kind: OutputKind,
) -> OutputSectionPartMap<u64> {
    let mut sizes = OutputSectionPartMap::with_size(NUM_SINGLE_PART_SECTIONS as usize);
    allocate_resolution(
        resolution.value_flags,
        resolution.resolution_flags,
        &mut sizes,
        output_kind,
    );
    sizes
}

fn allocate_resolution(
    value_flags: ValueFlags,
    resolution_flags: ResolutionFlags,
    mem_sizes: &mut OutputSectionPartMap<u64>,
    output_kind: OutputKind,
) {
    let has_dynamic_symbol = value_flags.is_dynamic() || resolution_flags.needs_export_dynamic();

    if resolution_flags.needs_got() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE);
        if resolution_flags.needs_plt() {
            mem_sizes.increment(part_id::PLT_GOT, elf::PLT_ENTRY_SIZE);
        }
        if value_flags.is_ifunc() {
            mem_sizes.increment(part_id::RELA_PLT, elf::RELA_ENTRY_SIZE);
        } else if value_flags.is_interposable() && has_dynamic_symbol {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        } else if value_flags.is_address() && output_kind.is_relocatable() {
            mem_sizes.increment(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
        }
    }

    if resolution_flags.needs_got_tls_offset() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE);
        if value_flags.is_interposable() || output_kind.is_shared_object() {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
    }

    if resolution_flags.needs_got_tls_module() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
        // For executables, the TLS module ID is known at link time. For shared objects, we
        // need a runtime relocation to fill it in.
        if !output_kind.is_executable() || value_flags.is_dynamic() {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
        if value_flags.is_interposable() && has_dynamic_symbol {
            mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
        }
    }

    if resolution_flags.needs_got_tls_descriptor() {
        mem_sizes.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
        mem_sizes.increment(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
    }
}

impl HandlerData for ObjectLayoutState<'_> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data> SymbolRequestHandler<'data> for ObjectLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        debug_assert_bail!(
            resources.symbol_db.is_canonical(symbol_id),
            "Tried to load symbol in a file that doesn't hold the definition: {}",
            resources.symbol_db.symbol_debug(symbol_id)
        );

        let object_symbol_index = self.symbol_id_range.id_to_input(symbol_id);
        let local_symbol = self.object.symbol(object_symbol_index)?;

        if let Some(section_id) = self
            .object
            .symbol_section(local_symbol, object_symbol_index)?
        {
            queue
                .local_work
                .push(WorkItem::LoadSection(SectionLoadRequest::new(
                    self.file_id,
                    section_id,
                )));
        } else if local_symbol.is_common(LittleEndian) {
            let common_symbol = CommonSymbol::new(local_symbol)?;
            common.allocate(
                output_section_id::BSS.part_id_with_alignment(common_symbol.alignment),
                common_symbol.size,
            );
        }

        Ok(())
    }
}

impl HandlerData for DynamicLayoutState<'_> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }

    fn file_id(&self) -> FileId {
        self.file_id
    }
}

impl<'data> SymbolRequestHandler<'data> for DynamicLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        _common: &mut CommonGroupState,
        symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        let local_index = symbol_id.to_offset(self.symbol_id_range());
        if let Some(&version_index) = self.symbol_versions.get(local_index) {
            let version_index = version_index.0.get(LittleEndian) & object::elf::VERSYM_VERSION;
            // Versions 0 and 1 are local and global. We care about the versions after that.
            if version_index > object::elf::VER_NDX_GLOBAL {
                *self
                    .symbol_versions_needed
                    .get_mut(version_index as usize - 1)
                    .with_context(|| format!("Invalid symbol version index {version_index}"))? =
                    true;
            }
        }
        Ok(())
    }
}

impl HandlerData for PreludeLayoutState<'_> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data> SymbolRequestHandler<'data> for PreludeLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        _common: &mut CommonGroupState,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        Ok(())
    }
}

impl HandlerData for LinkerScriptLayoutState<'_> {
    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }

    fn file_id(&self) -> FileId {
        self.file_id
    }
}

impl<'data> SymbolRequestHandler<'data> for LinkerScriptLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        _common: &mut CommonGroupState<'data>,
        _symbol_id: SymbolId,
        _resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        Ok(())
    }
}

impl HandlerData for EpilogueLayoutState<'_> {
    fn file_id(&self) -> FileId {
        self.file_id
    }

    fn symbol_id_range(&self) -> SymbolIdRange {
        self.symbol_id_range
    }
}

impl<'data> SymbolRequestHandler<'data> for EpilogueLayoutState<'data> {
    fn load_symbol<'scope, A: Arch>(
        &mut self,
        _common: &mut CommonGroupState,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        _queue: &mut LocalWorkQueue,
    ) -> Result {
        let def_info =
            &self.internal_symbols.symbol_definitions[self.symbol_id_range.id_to_offset(symbol_id)];

        if let Some(output_section_id) = def_info.section_id() {
            // We've gotten a request to load a __start_ / __stop_ symbol, sent requests to load all
            // sections that would go into that section.
            let sections = resources.start_stop_sections.get(output_section_id);
            while let Some(request) = sections.pop() {
                resources.send_work(request.file_id, WorkItem::LoadSection(request));
            }
        }

        Ok(())
    }
}

/// Attributes that we'll take from an input section and apply to the output section into which it's
/// placed.
#[derive(Clone, Copy)]
struct SectionAttributes {
    flags: SectionFlags,
    ty: SectionType,
    entsize: u64,
}

impl SectionAttributes {
    fn from_header(header: &crate::elf::SectionHeader) -> Self {
        Self {
            flags: SectionFlags::from_header(header),
            ty: SectionType::from_header(header),
            entsize: header.sh_entsize.get(LittleEndian),
        }
    }

    fn merge(&mut self, rhs: Self) {
        self.flags |= rhs.flags;

        // We somewhat arbitrarily tie-break by selecting the maximum type. This means for example
        // that types like SHT_INIT_ARRAY win out over more generic types like SHT_PROGBITS.
        self.ty = self.ty.max(rhs.ty);

        // If all input sections specify the same entsize, then we use that. If there's any
        // inconsistency, then we set entsize to 0.
        if self.entsize != rhs.entsize {
            self.entsize = 0;
        }
    }
}

struct CommonGroupState<'data> {
    mem_sizes: OutputSectionPartMap<u64>,

    section_attributes: OutputSectionMap<Option<SectionAttributes>>,

    /// Dynamic symbols that need to be defined. Because of the ordering requirements for symbol
    /// hashes, these get defined by the epilogue. The object on which a particular dynamic symbol
    /// is stored is non-deterministic and is whichever object first requested export of that
    /// symbol. That's OK though because the epilogue will sort all dynamic symbols.
    dynamic_symbol_definitions: Vec<DynamicSymbolDefinition<'data>>,
}

impl CommonGroupState<'_> {
    fn new(output_sections: &OutputSections) -> Self {
        Self {
            mem_sizes: output_sections.new_part_map(),
            section_attributes: output_sections.new_section_map(),
            dynamic_symbol_definitions: Default::default(),
        }
    }

    fn validate_sizes(&self) -> Result {
        if *self.mem_sizes.get(part_id::GNU_VERSION) > 0 {
            let num_dynamic_symbols =
                self.mem_sizes.get(part_id::DYNSYM) / crate::elf::SYMTAB_ENTRY_SIZE;
            let num_versym = self.mem_sizes.get(part_id::GNU_VERSION) / size_of::<Versym>() as u64;
            if num_versym != num_dynamic_symbols {
                bail!(
                    "Object has {num_dynamic_symbols} dynamic symbols, but \
                         has {num_versym} versym entries"
                );
            }
        }

        Ok(())
    }

    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        section_layouts: &OutputSectionMap<OutputRecordLayout>,
    ) -> u32 {
        // strtab
        let offset = memory_offsets.get_mut(part_id::STRTAB);
        let strtab_offset_start = (*offset
            - section_layouts.get(output_section_id::STRTAB).mem_offset)
            .try_into()
            .expect("Symbol string table overflowed 32 bits");
        *offset += self.mem_sizes.get(part_id::STRTAB);

        // symtab
        memory_offsets.increment(
            part_id::SYMTAB_LOCAL,
            *self.mem_sizes.get(part_id::SYMTAB_LOCAL),
        );
        memory_offsets.increment(
            part_id::SYMTAB_GLOBAL,
            *self.mem_sizes.get(part_id::SYMTAB_GLOBAL),
        );

        strtab_offset_start
    }

    fn allocate(&mut self, part_id: PartId, size: u64) {
        self.mem_sizes.increment(part_id, size);
    }

    /// Allocate resources and update attributes based on a section having been loaded.
    fn section_loaded(
        &mut self,
        part_id: PartId,
        header: &object::elf::SectionHeader64<LittleEndian>,
        section: Section,
    ) {
        self.allocate(part_id, section.capacity());
        self.store_section_attributes(part_id, header);
    }

    fn store_section_attributes(
        &mut self,
        part_id: PartId,
        header: &object::elf::SectionHeader64<LittleEndian>,
    ) {
        let existing_attributes = self.section_attributes.get_mut(part_id.output_section_id());

        let new_attributes = SectionAttributes::from_header(header);

        if let Some(existing) = existing_attributes {
            existing.merge(new_attributes);
        } else {
            *existing_attributes = Some(new_attributes);
        }
    }
}

fn create_global_address_emitter<'state>(
    symbol_resolution_flags: &'state [ResolutionFlags],
) -> GlobalAddressEmitter<'state> {
    GlobalAddressEmitter {
        symbol_resolution_flags,
    }
}

struct ObjectLayoutState<'data> {
    input: InputRef<'data>,
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    object: &'data File<'data>,

    /// Info about each of our sections. Indexed the same as the sections in the input object.
    sections: Vec<SectionSlot>,

    /// Mapping from sections to their corresponding relocation section.
    relocations: object::read::elf::RelocationSections,

    cies: SmallVec<[CieAtOffset<'data>; 2]>,

    eh_frame_section: Option<&'data object::elf::SectionHeader64<LittleEndian>>,
    eh_frame_size: u64,

    gnu_property_notes: Vec<GnuProperty>,
    riscv_attributes: Vec<RiscVAttribute>,

    /// Indexed by `FrameIndex`.
    exception_frames: Vec<ExceptionFrame<'data>>,
}

#[derive(Default)]
struct ExceptionFrame<'data> {
    /// The relocations that need to be processed if we load this frame.
    relocations: DynamicRelocationSequence<'data>,

    /// Number of bytes required to store this frame.
    frame_size: u32,

    /// The index of the previous frame that is for the same section.
    previous_frame_for_section: Option<FrameIndex>,
}

#[derive(Debug)]
pub(crate) struct GnuProperty {
    pub(crate) ptype: u32,
    pub(crate) data: u32,
}

#[derive(Debug)]
pub(crate) struct RiscVArch {
    map: IndexMap<String, (u64, u64)>,
}

impl RiscVArch {
    pub(crate) fn to_attribute_string(&self) -> String {
        self.map
            .iter()
            .map(|(arch, (major, minor))| format!("{arch}{major}p{minor}"))
            .join("_")
            .clone()
    }
}

#[derive(Debug)]
pub(crate) enum RiscVAttribute {
    /// Indicates the stack alignment requirement in bytes.
    StackAlign(u64),
    /// Indicates the target architecture of this object.
    Arch(RiscVArch),
    /// Indicates whether to impose unaligned memory accesses in code generation.
    UnalignedAccess(bool),
    /// Indicates the major version of the privileged specification.
    PrivilegedSpecMajor(u64),
    /// Indicates the major version of the privileged specification.
    PrivilegedSpecMinor(u64),
    /// Indicates the revision version of the privileged specification.
    PrivilegedSpecRevision(u64),
}

#[derive(Default)]
struct LocalWorkQueue {
    /// The index of the worker that owns this queue.
    index: usize,

    /// Work that needs to be processed by the worker that owns this queue.
    local_work: Vec<WorkItem>,
}

bitflags! {
    /// What kind of resolution we want for a symbol or section.
    #[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
    pub(crate) struct ResolutionFlags: u8 {
        /// The direct value is needed. e.g. via a relative or absolute relocation that doesn't use the
        /// PLT or GOT.
        const DIRECT = 1 << 0;

        /// An address in the global offset table is needed.
        const GOT = 1 << 1;

        /// A PLT entry is needed.
        const PLT = 1 << 2;

        /// A double GOT entry is needed in order to store the module number and offset within the
        /// module. Only set for TLS variables.
        const GOT_TLS_MODULE = 1 << 3;

        /// A single GOT entry is needed to store the offset of the TLS variable within the initial
        /// TLS block.
        const GOT_TLS_OFFSET = 1 << 4;

        /// A double GOT entry is needed in order to store the function pointer and a pointer that
        /// points to a pair of words (module number and offset within the module).
        /// Only set for TLS variables.
        const GOT_TLS_DESCRIPTOR = 1 << 5;

        /// The request originated from a dynamic object, so the symbol should be put into the dynamic
        /// symbol table.
        const EXPORT_DYNAMIC = 1 << 6;

        /// We encountered a direct reference to a symbol from a non-writable section and so we're
        /// going to need to do a copy relocation. Note that multiple symbols can have this flag
        /// set, however if they all point at the same address in the shared object from which they
        /// originate, only a single copy relocation will be emitted. This flag indicates that the
        /// symbol requires a copy relocation, not necessarily that a copy relocation will be
        /// emitted with the exact name of this symbol.
        const COPY_RELOCATION = 1 << 7;
    }
}

pub(crate) struct AtomicResolutionFlags {
    value: AtomicU8,
}

impl ResolutionFlags {
    #[must_use]
    pub(crate) fn needs_direct(self) -> bool {
        self.contains(ResolutionFlags::DIRECT)
    }

    #[must_use]
    pub(crate) fn needs_copy_relocation(self) -> bool {
        self.contains(ResolutionFlags::COPY_RELOCATION)
    }

    #[must_use]
    pub(crate) fn needs_export_dynamic(self) -> bool {
        self.contains(ResolutionFlags::EXPORT_DYNAMIC)
    }

    #[must_use]
    pub(crate) fn needs_got(self) -> bool {
        self.contains(ResolutionFlags::GOT)
    }

    #[must_use]
    pub(crate) fn needs_plt(self) -> bool {
        self.contains(ResolutionFlags::PLT)
    }

    #[must_use]
    pub(crate) fn needs_got_tls_offset(self) -> bool {
        self.contains(ResolutionFlags::GOT_TLS_OFFSET)
    }

    #[must_use]
    pub(crate) fn needs_got_tls_module(self) -> bool {
        self.contains(ResolutionFlags::GOT_TLS_MODULE)
    }

    #[must_use]
    pub(crate) fn needs_got_tls_descriptor(self) -> bool {
        self.contains(ResolutionFlags::GOT_TLS_DESCRIPTOR)
    }
}

impl AtomicResolutionFlags {
    fn empty() -> Self {
        Self::new(ResolutionFlags::empty())
    }

    fn new(flags: ResolutionFlags) -> Self {
        Self {
            value: AtomicU8::new(flags.bits()),
        }
    }

    fn into_non_atomic(self) -> ResolutionFlags {
        ResolutionFlags::from_bits_retain(self.value.into_inner())
    }

    fn fetch_or(&self, flags: ResolutionFlags) -> ResolutionFlags {
        // Calling fetch_or on our atomic requires that we gain exclusive access to the cache line
        // containing the atomic. If all the bits are already set, then that's wasteful, so we first
        // check if the bits are set and if they are, we skip the fetch_or call.
        let current_bits = self.value.load(atomic::Ordering::Relaxed);
        if current_bits & flags.bits() == flags.bits() {
            return ResolutionFlags::from_bits_retain(current_bits);
        }
        let previous_bits = self.value.fetch_or(flags.bits(), atomic::Ordering::Relaxed);
        ResolutionFlags::from_bits_retain(previous_bits)
    }

    pub(crate) fn get(&self) -> ResolutionFlags {
        ResolutionFlags::from_bits_retain(self.value.load(atomic::Ordering::Relaxed))
    }
}

impl Clone for AtomicResolutionFlags {
    fn clone(&self) -> Self {
        Self {
            value: AtomicU8::new(self.value.load(atomic::Ordering::Relaxed)),
        }
    }
}

struct DynamicLayoutState<'data> {
    object: &'data File<'data>,
    input: InputRef<'data>,
    file_id: FileId,
    symbol_id_range: SymbolIdRange,
    lib_name: &'data [u8],

    /// Which symbol versions are needed. A symbol version is needed if a symbol with that version
    /// has been loaded. The first version has index 1, so we store it at offset 0.
    symbol_versions_needed: Vec<bool>,

    /// The contents of the .gnu.version section. Maps from symbol index to symbol version index.
    symbol_versions: &'data [Versym],

    verneed_info: Option<VerneedInfo<'data>>,

    non_addressable_indexes: NonAddressableIndexes,

    /// Maps from addresses within the shared object to copy relocations at that address.
    copy_relocations: HashMap<u64, CopyRelocationInfo>,
}

struct CopyRelocationInfo {
    /// The symbol ID for which we'll actually generate the copy relocation. Initially, this is just
    /// the first symbol at a particular address for which we requested a copy relocation, then
    /// later we may update it to point to a different symbol if that first symbol was weak.
    symbol_id: SymbolId,

    is_weak: bool,
}

pub(crate) struct VerneedInfo<'data> {
    pub(crate) defs: VerdefIterator<'data, FileHeader>,
    pub(crate) string_table_index: object::SectionIndex,

    /// Number of symbol versions that we're going to emit. This is the number of entries in
    /// `symbol_versions_needed` that are true. Computed after graph traversal.
    pub(crate) version_count: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct DynamicSymbolDefinition<'data> {
    pub(crate) symbol_id: SymbolId,
    pub(crate) name: &'data [u8],
    pub(crate) hash: u32,
    pub(crate) version: u16,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Section {
    pub(crate) index: object::SectionIndex,
    pub(crate) part_id: PartId,
    /// Size in memory.
    pub(crate) size: u64,
    pub(crate) resolution_flags: ResolutionFlags,
    pub(crate) is_writable: bool,
}

pub(crate) struct GroupLayout<'data> {
    pub(crate) files: Vec<FileLayout<'data>>,

    /// The offset in .dynstr at which we'll start writing.
    pub(crate) dynstr_start_offset: u32,

    /// The offset in .strtab at which we'll start writing.
    pub(crate) strtab_start_offset: u32,

    pub(crate) eh_frame_start_address: u64,

    pub(crate) mem_sizes: OutputSectionPartMap<u64>,
    pub(crate) file_sizes: OutputSectionPartMap<usize>,
}

struct GroupState<'data> {
    queue: LocalWorkQueue,
    files: Vec<FileLayoutState<'data>>,
    common: CommonGroupState<'data>,
    num_symbols: usize,
}

/// The sizes and positions of either a segment or an output section. Note, we use usize for file
/// offsets and sizes, since we mmap our output file, so we're frequently working with in-memory
/// slices. This means that if we were linking on a 32 bit system that we'd be limited to file
/// offsets that were 32 bits. This isn't a loss though, since we couldn't mmap an output file where
/// that would be a problem on a 32 bit system.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OutputRecordLayout {
    pub(crate) file_size: usize,
    pub(crate) mem_size: u64,
    pub(crate) alignment: Alignment,
    pub(crate) file_offset: usize,
    pub(crate) mem_offset: u64,
}

struct GraphResources<'data, 'scope> {
    symbol_db: &'scope SymbolDb<'data>,

    worker_slots: Vec<Mutex<WorkerSlot<'data>>>,

    errors: Mutex<Vec<Error>>,

    waiting_workers: ArrayQueue<GroupState<'data>>,

    /// A queue in which we store threads when they're idle so that other threads can wake them up
    /// when more work comes in. We always have one less slot in this array than the number of
    /// threads, since we never want all threads to be idle because that means we're finished. None
    /// if we're running with a single thread - mostly because ArrayQueue panics if we try to create
    /// an instance with zero size.
    idle_threads: Option<ArrayQueue<std::thread::Thread>>,

    done: AtomicBool,

    symbol_resolution_flags: &'scope [AtomicResolutionFlags],

    /// Which sections have we loaded an input section into. This is not the same as checking
    /// whether the mem sizes for that section are non-zero because we can load an input section
    /// with size 0. If we do that, we still need to produce the output section so that we have
    /// something to refer to in the symtab.
    sections_with_content: OutputSectionMap<AtomicBool>,

    merged_strings: &'scope OutputSectionMap<MergedStringsSection<'data>>,

    has_static_tls: AtomicBool,

    uses_tlsld: AtomicBool,

    /// For each OutputSectionId, this tracks a list of sections that should be loaded if that
    /// section gets referenced. The sections here will only be those that are eligible for having
    /// __start_ / __stop_ symbols. i.e. sections that don't start their names with a ".".
    start_stop_sections: OutputSectionMap<SegQueue<SectionLoadRequest>>,

    input_data: &'scope InputData<'data>,
}

struct FinaliseLayoutResources<'scope, 'data> {
    symbol_db: &'scope SymbolDb<'data>,
    symbol_resolution_flags: &'scope [ResolutionFlags],
    output_sections: &'scope OutputSections<'data>,
    output_order: &'scope OutputOrder,
    section_layouts: &'scope OutputSectionMap<OutputRecordLayout>,
    merged_string_start_addresses: &'scope MergedStringStartAddresses,
    merged_strings: &'scope OutputSectionMap<MergedStringsSection<'data>>,
}

#[derive(Copy, Clone, Debug)]
enum WorkItem {
    /// The symbol's resolution flags have been made non-empty. The object that owns the symbol
    /// should perform any additional actions required, e.g. load the section that contains the
    /// symbol and process any relocations for that section.
    LoadGlobalSymbol(SymbolId),

    /// A direct reference to a dynamic symbol has been encountered. The symbol should be defined in
    /// BSS with a copy relocation.
    CopyRelocateSymbol(SymbolId),

    /// A request to load a particular section.
    LoadSection(SectionLoadRequest),

    /// Requests that the specified symbol be exported as a dynamic symbol. Will be ignored if the
    /// object that defines the symbol is not loaded or is itself a shared object.
    ExportDynamic(SymbolId),
}

#[derive(Copy, Clone, Debug)]
struct SectionLoadRequest {
    file_id: FileId,

    /// The offset of the section within the file's sections. i.e. the same as object::SectionIndex,
    /// but stored as a u32 for compactness.
    section_index: u32,
}

impl WorkItem {
    fn file_id(self, symbol_db: &SymbolDb) -> FileId {
        match self {
            WorkItem::LoadGlobalSymbol(s) | WorkItem::CopyRelocateSymbol(s) => {
                symbol_db.file_id_for_symbol(s)
            }
            WorkItem::LoadSection(s) => s.file_id,
            WorkItem::ExportDynamic(symbol_id) => symbol_db.file_id_for_symbol(symbol_id),
        }
    }
}

impl<'data> Layout<'data> {
    pub(crate) fn prelude(&self) -> &PreludeLayout<'data> {
        let Some(FileLayout::Prelude(i)) = self.group_layouts.first().and_then(|g| g.files.first())
        else {
            panic!("Prelude layout not found at expected offset");
        };
        i
    }

    pub(crate) fn args(&self) -> &'data Args {
        self.symbol_db.args
    }

    pub(crate) fn symbol_debug(&self, symbol_id: SymbolId) -> SymbolDebug<'_, 'data> {
        self.symbol_db.symbol_debug(symbol_id)
    }

    #[inline(always)]
    pub(crate) fn merged_symbol_resolution(&self, symbol_id: SymbolId) -> Option<Resolution> {
        self.local_symbol_resolution(self.symbol_db.definition(symbol_id))
            .copied()
            .map(|mut res| {
                res.value_flags
                    .merge(self.symbol_db.symbol_value_flags(symbol_id));
                res
            })
    }

    pub(crate) fn local_symbol_resolution(&self, symbol_id: SymbolId) -> Option<&Resolution> {
        self.symbol_resolutions.resolutions[symbol_id.as_usize()].as_ref()
    }

    pub(crate) fn resolutions_in_range(
        &self,
        range: SymbolIdRange,
    ) -> impl Iterator<Item = (SymbolId, Option<&Resolution>)> {
        self.symbol_resolutions.resolutions[range.as_usize()]
            .iter()
            .enumerate()
            .map(move |(i, res)| (range.offset_to_id(i), res.as_ref()))
    }

    pub(crate) fn entry_symbol_address(&self) -> Result<u64> {
        let Some(symbol_id) = self.prelude().entry_symbol_id else {
            if self.args().output_kind() == OutputKind::SharedObject {
                // Shared objects don't have an implicit entry point.
                return Ok(0);
            }

            // There's no entry point specified, set it to the start of .text. This is pretty weird,
            // but it's what GNU ld does.
            let text_layout = self.section_layouts.get(output_section_id::TEXT);
            if text_layout.mem_size == 0 {
                crate::error::warning(
                    "cannot find entry symbol `_start` and .text is empty, not setting entry point",
                );

                return Ok(0);
            }

            crate::error::warning(&format!(
                "cannot find entry symbol `_start`, defaulting to 0x{}",
                text_layout.mem_offset
            ));
            return Ok(text_layout.mem_offset);
        };

        let resolution = self.local_symbol_resolution(symbol_id).with_context(|| {
            format!(
                "Entry point symbol was defined, but didn't get loaded. {}",
                self.symbol_debug(symbol_id)
            )
        })?;

        if !resolution.value_flags().is_address() && !resolution.value_flags().is_absolute() {
            bail!(
                "Entry point must be an address or absolute value. {}",
                self.symbol_debug(symbol_id)
            );
        }

        Ok(resolution.value())
    }

    pub(crate) fn tls_start_address(&self) -> u64 {
        // If we don't have a TLS segment then the value we return won't really matter.
        self.segment_layouts
            .tls_layout
            .as_ref()
            .map_or(0, |seg| seg.mem_offset)
    }

    /// Returns the memory address of the end of the TLS segment including any padding required to
    /// make sure that the TCB will be usize-aligned.
    pub(crate) fn tls_end_address(&self) -> u64 {
        self.segment_layouts.tls_layout.as_ref().map_or(0, |seg| {
            seg.alignment.align_up(seg.mem_offset + seg.mem_size)
        })
    }

    /// Returns the memory address of the start of the TLS segment used by the AArch64.
    pub(crate) fn tls_start_address_aarch64(&self) -> u64 {
        self.segment_layouts.tls_layout.as_ref().map_or(0, |seg| {
            // Two words at TP are reserved by the arch.
            seg.alignment.align_down(seg.mem_offset - 2 * 8)
        })
    }

    pub(crate) fn layout_data(&self) -> linker_layout::Layout {
        let files = self
            .group_layouts
            .iter()
            .flat_map(|group| {
                group.files.iter().filter_map(|file| match file {
                    FileLayout::Object(obj) => Some(linker_layout::InputFile {
                        path: obj.input.file.filename.clone(),
                        archive_entry: obj.input.entry.as_ref().map(|e| {
                            linker_layout::ArchiveEntryInfo {
                                range: e.from.clone(),
                                identifier: e.identifier.as_slice().to_owned(),
                            }
                        }),
                        sections: obj
                            .section_resolutions
                            .iter()
                            .zip(obj.object.sections.iter())
                            .zip(&obj.sections)
                            .map(|((res, section), section_slot)| {
                                (matches!(section_slot, SectionSlot::Loaded(..))
                                    && SectionFlags::from_header(section).contains(shf::ALLOC)
                                    && obj.object.section_size(section).is_ok_and(|s| s > 0))
                                .then(|| {
                                    let address = res.address;
                                    linker_layout::Section {
                                        mem_range: address
                                            ..(address + obj.object.section_size(section).unwrap()),
                                    }
                                })
                            })
                            .collect(),
                    }),
                    _ => None,
                })
            })
            .collect();
        linker_layout::Layout { files }
    }

    pub(crate) fn resolution_flags_for_symbol(&self, symbol_id: SymbolId) -> ResolutionFlags {
        self.symbol_resolution_flags[symbol_id.as_usize()]
    }

    pub(crate) fn file_layout(&self, file_id: FileId) -> &FileLayout<'data> {
        let group_layout = &self.group_layouts[file_id.group()];
        &group_layout.files[file_id.file()]
    }

    /// Returns the base address of the global offset table. This needs to be consistent with the
    /// symbol `_GLOBAL_OFFSET_TABLE_`.
    pub(crate) fn got_base(&self) -> u64 {
        let got_layout = self.section_layouts.get(output_section_id::GOT);
        got_layout.mem_offset
    }

    /// Returns whether we're going to output the .gnu.version section.
    pub(crate) fn gnu_version_enabled(&self) -> bool {
        self.section_part_layouts
            .get(part_id::GNU_VERSION)
            .file_size
            > 0
    }

    pub(crate) fn info_inputs<'layout>(&'layout self) -> InfoInputs<'layout> {
        InfoInputs {
            section_part_layouts: &self.section_part_layouts,
            non_addressable_counts: &self.non_addressable_counts,
            output_section_indexes: &self.output_sections.output_section_indexes,
        }
    }
}

fn layout_sections(
    output_sections: &OutputSections,
    section_part_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> OutputSectionMap<OutputRecordLayout> {
    section_part_layouts.merge_parts(|section_id, layouts| {
        let info = output_sections.section_infos.get(section_id);
        let mut file_offset = usize::MAX;
        let mut mem_offset = u64::MAX;
        let mut file_end = 0;
        let mut mem_end = 0;
        let mut alignment = info.min_alignment;

        for part in layouts {
            file_offset = file_offset.min(part.file_offset);
            mem_offset = mem_offset.min(part.mem_offset);
            file_end = file_end.max(part.file_offset + part.file_size);
            mem_end = mem_end.max(part.mem_offset + part.mem_size);
            if part.mem_size > 0 {
                alignment = alignment.max(part.alignment);
            }
        }
        OutputRecordLayout {
            file_size: file_end - file_offset,
            mem_size: mem_end - mem_offset,
            alignment,
            file_offset,
            mem_offset,
        }
    })
}

#[tracing::instrument(skip_all, name = "Compute per-group start offsets")]
fn compute_start_offsets_by_group(
    group_states: &[GroupState<'_>],
    mut mem_offsets: OutputSectionPartMap<u64>,
) -> Vec<OutputSectionPartMap<u64>> {
    group_states
        .iter()
        .map(|group| {
            let group_mem_starts = mem_offsets.clone();
            mem_offsets.merge(&group.common.mem_sizes);
            group_mem_starts
        })
        .collect_vec()
}

#[tracing::instrument(skip_all, name = "Assign symbol addresses")]
fn compute_symbols_and_layouts<'data>(
    group_states: Vec<GroupState<'data>>,
    starting_mem_offsets_by_group: Vec<OutputSectionPartMap<u64>>,
    per_group_res_writers: &mut [sharded_vec_writer::Shard<Option<Resolution>>],
    resources: &FinaliseLayoutResources<'_, 'data>,
) -> Result<Vec<GroupLayout<'data>>> {
    group_states
        .into_par_iter()
        .zip(starting_mem_offsets_by_group)
        .zip(per_group_res_writers)
        .map(|((state, mut memory_offsets), symbols_out)| {
            if cfg!(debug_assertions) {
                let offset_verifier = crate::verification::OffsetVerifier::new(
                    &memory_offsets,
                    &state.common.mem_sizes,
                );

                // Make sure that ignored offsets really aren't used by `finalise_layout` by setting
                // them to an arbitrary value. If they are used, we'll quickly notice.
                crate::verification::clear_ignored(&mut memory_offsets);

                let layout = state.finalise_layout(&mut memory_offsets, symbols_out, resources)?;

                offset_verifier.verify(
                    &memory_offsets,
                    resources.output_sections,
                    resources.output_order,
                    &layout.files,
                )?;
                Ok(layout)
            } else {
                state.finalise_layout(&mut memory_offsets, symbols_out, resources)
            }
        })
        .collect()
}

#[tracing::instrument(skip_all, name = "Compute segment layouts")]
fn compute_segment_layout(
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
    output_sections: &OutputSections,
    output_order: &OutputOrder,
    program_segments: &ProgramSegments,
    header_info: &HeaderInfo,
) -> Result<SegmentLayouts> {
    #[derive(Clone)]
    struct Record {
        segment_id: ProgramSegmentId,
        file_start: usize,
        file_end: usize,
        mem_start: u64,
        mem_end: u64,
        alignment: Alignment,
    }

    use output_section_id::OrderEvent;
    let mut complete = Vec::with_capacity(program_segments.len());
    let mut active_segments = vec![None; program_segments.len()];

    for event in output_order {
        match event {
            OrderEvent::SegmentStart(segment_id) => {
                if program_segments.is_stack_segment(segment_id) {
                    // STACK segment is special as it does not contain any section.
                    active_segments[segment_id.as_usize()] = Some(Record {
                        segment_id,
                        file_start: 0,
                        file_end: 0,
                        mem_start: 0,
                        mem_end: 0,
                        alignment: alignment::MIN,
                    });
                } else {
                    active_segments[segment_id.as_usize()] = Some(Record {
                        segment_id,
                        file_start: usize::MAX,
                        file_end: 0,
                        mem_start: u64::MAX,
                        mem_end: 0,
                        alignment: alignment::MIN,
                    });
                }
            }
            OrderEvent::SegmentEnd(segment_id) => {
                let record = active_segments[segment_id.as_usize()]
                    .take()
                    .context("SegmentEnd without matching SegmentStart")?;

                complete.push(record);
            }
            OrderEvent::Section(section_id) => {
                let section_layout = section_layouts.get(section_id);
                let merge_target = output_sections.primary_output_section(section_id);

                // Skip all ignored sections that will not end up in the final file.
                if section_layout.file_size == 0
                    && section_layout.mem_size == 0
                    && output_sections.output_section_indexes[merge_target.as_usize()].is_none()
                {
                    continue;
                }
                let section_flags = output_sections.section_flags(merge_target);

                if active_segments.iter().all(|s| s.is_none()) {
                    ensure!(
                        section_layout.mem_offset == 0,
                        "Expected zero address for section {} not present in any program segment.",
                        output_sections.section_debug(section_id)
                    );
                    ensure!(
                        !section_flags.contains(shf::ALLOC),
                        "Section with SHF_ALLOC flag {} not present in any program segment.",
                        output_sections.section_debug(section_id)
                    );
                } else {
                    // RISCV_ATTRIBUTES segment is kind of special as it maps a section that is non-ALLOC.
                    if section_id == output_section_id::RISCV_ATTRIBUTES {
                    } else {
                        // All segments should only cover sections that are allocated and have a non-zero address.
                        ensure!(
                            section_layout.mem_offset != 0 || merge_target == FILE_HEADER,
                            "Missing memory offset for section {} present in a program segment.",
                            output_sections.section_debug(section_id),
                        );
                        ensure!(
                            section_flags.contains(shf::ALLOC),
                            "Missing SHF_ALLOC section flag for section {} present in a program \
                         segment.",
                            output_sections.section_debug(section_id)
                        );
                    }
                    for opt_rec in &mut active_segments {
                        let Some(rec) = opt_rec.as_mut() else {
                            continue;
                        };

                        rec.file_start = rec.file_start.min(section_layout.file_offset);
                        rec.mem_start = rec.mem_start.min(section_layout.mem_offset);
                        rec.file_end = rec
                            .file_end
                            .max(section_layout.file_offset + section_layout.file_size);
                        rec.mem_end = rec
                            .mem_end
                            .max(section_layout.mem_offset + section_layout.mem_size);
                        rec.alignment = rec.alignment.max(section_layout.alignment);
                    }
                }
            }
            OrderEvent::SetLocation(_) => {}
        }
    }

    complete.sort_by_key(|r| r.segment_id);

    assert_eq!(complete.len(), program_segments.len());
    let mut tls_layout = None;

    let mut segments: Vec<SegmentLayout> = header_info
        .active_segment_ids
        .iter()
        .map(|&id| {
            let r = &complete[id.as_usize()];

            let sizes = OutputRecordLayout {
                file_size: r.file_end - r.file_start,
                mem_size: r.mem_end - r.mem_start,
                alignment: r.alignment,
                file_offset: r.file_start,
                mem_offset: r.mem_start,
            };

            if program_segments.is_tls_segment(id) {
                tls_layout = Some(sizes);
            }

            SegmentLayout { id, sizes }
        })
        .collect();

    segments.sort_by_key(|s| program_segments.order_key(s.id, s.sizes.mem_offset));

    Ok(SegmentLayouts {
        segments,
        tls_layout,
    })
}

#[tracing::instrument(skip_all, name = "Compute total section sizes")]
fn compute_total_section_part_sizes(
    group_states: &mut [GroupState],
    output_sections: &mut OutputSections,
    output_order: &OutputOrder,
    program_segments: &ProgramSegments,
    symbol_resolution_flags: &mut [ResolutionFlags],
    sections_with_content: OutputSectionMap<bool>,
    symbol_db: &SymbolDb,
) -> Result<OutputSectionPartMap<u64>> {
    let mut total_sizes: OutputSectionPartMap<u64> = output_sections.new_part_map();
    for group_state in group_states.iter() {
        total_sizes.merge(&group_state.common.mem_sizes);
    }

    let first_group = group_states.first_mut().unwrap();
    let Some(FileLayoutState::Prelude(internal_layout)) = first_group.files.first_mut() else {
        unreachable!();
    };

    internal_layout.apply_late_size_adjustments(
        &mut first_group.common,
        &mut total_sizes,
        sections_with_content,
        output_sections,
        output_order,
        program_segments,
        symbol_resolution_flags,
        symbol_db,
    )?;

    Ok(total_sizes)
}

/// Section flags that should be propagated from input sections to the output section in which they
/// are placed. Note, the inversion, so we keep all flags other than the one listed here.
const SECTION_FLAGS_PROPAGATION_MASK: SectionFlags =
    SectionFlags::from_u32(!object::elf::SHF_GROUP);

/// Propagates attributes from input sections to the output sections into which they were placed.
#[tracing::instrument(skip_all, name = "Propagate section attributes")]
fn propagate_section_attributes(group_states: &[GroupState], output_sections: &mut OutputSections) {
    for group_state in group_states {
        group_state
            .common
            .section_attributes
            .for_each(|section_id, attributes| {
                if let Some(attributes) = attributes {
                    attributes.apply(output_sections, section_id);
                }
            });
    }
}

impl SectionAttributes {
    pub(crate) fn apply(&self, output_sections: &mut OutputSections, section_id: OutputSectionId) {
        let info = output_sections.section_infos.get_mut(section_id);

        info.section_flags |= self.flags & SECTION_FLAGS_PROPAGATION_MASK;

        info.entsize = self.entsize;

        info.ty = info.ty.max(self.ty);
    }
}

/// This is similar to computing start addresses, but is used for things that aren't addressable,
/// but which need to be unique. It's non parallel. It could potentially be run in parallel with
/// some of the stages that run after it, that don't need access to the file states.
#[tracing::instrument(skip_all, name = "Apply non-addressable indexes")]
fn apply_non_addressable_indexes(
    group_states: &mut [GroupState],
    symbol_db: &SymbolDb,
) -> Result<NonAddressableCounts> {
    let mut indexes = NonAddressableIndexes {
        // Allocate version indexes starting from after the local and global indexes and any
        // versions defined by a version script.
        gnu_version_r_index: object::elf::VER_NDX_GLOBAL
            + 1.max(symbol_db.version_script.version_count()),
    };

    let mut counts = NonAddressableCounts {
        verneed_count: 0,
        verdef_count: 0,
    };

    for g in group_states.iter_mut() {
        for s in &mut g.files {
            match s {
                FileLayoutState::Dynamic(s) => {
                    s.apply_non_addressable_indexes(&mut indexes, &mut counts)?;
                }
                FileLayoutState::Epilogue(s) => {
                    counts.verdef_count += s
                        .verdefs
                        .as_ref()
                        .map(|v| v.len() as u16)
                        .unwrap_or_default();
                }
                _ => {}
            }
        }
    }

    // If we were going to output symbol versions, but we didn't actually use any, then we drop all
    // versym allocations. This is partly to avoid wasting unnecessary space in the output file, but
    // mostly in order match what GNU ld does.
    if (counts.verneed_count == 0 && counts.verdef_count == 0)
        && symbol_db.args.should_output_symbol_versions()
    {
        for g in group_states {
            *g.common.mem_sizes.get_mut(part_id::GNU_VERSION) = 0;
        }
    }
    Ok(counts)
}

#[derive(Clone, Copy, Default)]
struct NonAddressableIndexes {
    gnu_version_r_index: u16,
}

#[derive(Copy, Clone)]
pub(crate) struct NonAddressableCounts {
    /// The number of shared objects that want to emit a verneed record.
    pub(crate) verneed_count: u64,
    /// The number of verdef records provided in version script.
    pub(crate) verdef_count: u16,
}

/// Returns the starting memory address for each alignment within each segment.
#[tracing::instrument(skip_all, name = "Compute per-alignment offsets")]
fn starting_memory_offsets(
    section_layouts: &OutputSectionPartMap<OutputRecordLayout>,
) -> OutputSectionPartMap<u64> {
    section_layouts.map(|_, rec| rec.mem_offset)
}

#[derive(Default)]
struct WorkerSlot<'data> {
    work: Vec<WorkItem>,
    worker: Option<GroupState<'data>>,
}

struct GcOutputs<'data> {
    group_states: Vec<GroupState<'data>>,
    sections_with_content: OutputSectionMap<bool>,
    has_static_tls: bool,
}

#[tracing::instrument(skip_all, name = "Find required sections")]
fn find_required_sections<'data, A: Arch>(
    groups_in: Vec<resolution::ResolvedGroup<'data>>,
    symbol_db: &SymbolDb<'data>,
    output_sections: &OutputSections<'data>,
    symbol_resolution_flags: &[AtomicResolutionFlags],
    merged_strings: &OutputSectionMap<MergedStringsSection<'data>>,
    input_data: &InputData<'data>,
) -> Result<GcOutputs<'data>> {
    let num_workers = groups_in.len();
    let (worker_slots, groups) = create_worker_slots(groups_in, output_sections, symbol_db);

    let num_threads = symbol_db.args.available_threads.get();

    let idle_threads = (num_threads > 1).then(|| ArrayQueue::new(num_threads - 1));
    let resources = GraphResources {
        symbol_db,
        worker_slots,
        errors: Mutex::new(Vec::new()),
        waiting_workers: ArrayQueue::new(num_workers),
        // NB, the -1 is because we never want all our threads to be idle. Once the last thread is
        // about to go idle, we're done and need to wake up and terminate all the threads.
        idle_threads,
        done: AtomicBool::new(false),
        symbol_resolution_flags,
        sections_with_content: output_sections.new_section_map(),
        merged_strings,
        has_static_tls: AtomicBool::new(false),
        uses_tlsld: AtomicBool::new(false),
        start_stop_sections: output_sections.new_section_map(),
        input_data,
    };
    let resources_ref = &resources;

    groups
        .into_par_iter()
        .enumerate()
        .try_for_each(|(i, mut group)| -> Result {
            let _span = tracing::debug_span!("find_required_sections", gid = i).entered();
            for file in &mut group.files {
                activate::<A>(&mut group.common, file, &mut group.queue, resources_ref)
                    .with_context(|| format!("Failed to activate {file}"))?;
            }
            let _ = resources_ref.waiting_workers.push(group);
            Ok(())
        })?;

    rayon::scope(|scope| {
        scope.spawn_broadcast(|_, _| {
            let panic_result = std::panic::catch_unwind(|| {
                let mut idle = false;
                while !resources.done.load(atomic::Ordering::SeqCst) {
                    while let Some(worker) = resources.waiting_workers.pop() {
                        worker.do_pending_work::<A>(resources_ref);
                    }
                    if idle {
                        // Wait until there's more work to do or until we shut down.
                        std::thread::park();
                        idle = false;
                    } else {
                        if resources.idle_threads.as_ref().is_none_or(|idle_threads| {
                            idle_threads.push(std::thread::current()).is_err()
                        }) {
                            // We're the only thread running. Either because there is only one
                            // thread (resources.idle_threads is None) or because all other threads
                            // are sleeping (resources.idle_threads is full). We're idle and all the
                            // other threads are too. Time to shut down.
                            resources.shut_down();
                            break;
                        }
                        idle = true;
                        // Go around the loop again before we park the thread. This ensures that we
                        // check for waiting workers in between when we added our thread to the idle
                        // list and when we park.
                    }
                }
            });
            // Make sure we shut down if one of our threads panics, otherwise our other threads
            // will wait indefinitely for the thread that panicked to finish its work.
            if panic_result.is_err() {
                resources.shut_down();
            }
        });
    });

    let mut errors: Vec<Error> = take(resources.errors.lock().unwrap().as_mut());
    // TODO: Figure out good way to report more than one error.
    if let Some(error) = errors.pop() {
        return Err(error);
    }

    let mut group_states = unwrap_worker_states(&resources.worker_slots);
    let sections_with_content = resources.sections_with_content.into_map(|v| v.into_inner());

    // Give our prelude a chance to tie up a few last sizes while we still have access to
    // `resources`.
    let prelude_group = &mut group_states[0];
    let FileLayoutState::Prelude(prelude) = &mut prelude_group.files[0] else {
        unreachable!("Prelude must be first");
    };
    prelude.pre_finalise_sizes(
        &mut prelude_group.common,
        &resources.uses_tlsld,
        resources.symbol_db.args,
    );

    Ok(GcOutputs {
        group_states,
        sections_with_content,
        has_static_tls: resources.has_static_tls.load(atomic::Ordering::Relaxed),
    })
}

fn create_worker_slots<'data>(
    groups_in: Vec<resolution::ResolvedGroup<'data>>,
    output_sections: &OutputSections<'data>,
    symbol_db: &SymbolDb<'data>,
) -> (Vec<Mutex<WorkerSlot<'data>>>, Vec<GroupState<'data>>) {
    let mut worker_slots = Vec::with_capacity(groups_in.len());
    let group_states = groups_in
        .into_iter()
        .enumerate()
        .zip(&symbol_db.num_symbols_per_group)
        .map(|((group_index, group), &num_symbols)| {
            let files = group
                .files
                .into_iter()
                .map(|file| file.create_layout_state())
                .collect();
            worker_slots.push(Mutex::new(WorkerSlot {
                work: Default::default(),
                worker: None,
            }));
            GroupState {
                queue: LocalWorkQueue::new(group_index),
                num_symbols,
                files,
                common: CommonGroupState::new(output_sections),
            }
        })
        .collect();
    (worker_slots, group_states)
}

fn unwrap_worker_states<'data>(
    worker_slots: &[Mutex<WorkerSlot<'data>>],
) -> Vec<GroupState<'data>> {
    worker_slots
        .iter()
        .filter_map(|w| w.lock().unwrap().worker.take())
        .collect()
}

impl<'data> GroupState<'data> {
    /// Does work until there's nothing left in the queue, then returns our worker to its slot and
    /// shuts down.
    fn do_pending_work<'scope, A: Arch>(mut self, resources: &GraphResources<'data, 'scope>) {
        loop {
            while let Some(work_item) = self.queue.local_work.pop() {
                let file_id = work_item.file_id(resources.symbol_db);
                let file = &mut self.files[file_id.file()];
                if let Err(error) =
                    file.do_work::<A>(&mut self.common, work_item, resources, &mut self.queue)
                {
                    resources.report_error(error);
                    return;
                }
            }
            {
                let mut slot = resources.worker_slots[self.queue.index].lock().unwrap();
                if slot.work.is_empty() {
                    slot.worker = Some(self);
                    return;
                }
                swap(&mut slot.work, &mut self.queue.local_work);
            };
        }
    }

    fn finalise_sizes(
        &mut self,
        symbol_db: &SymbolDb<'data>,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        for file_state in &mut self.files {
            file_state.finalise_sizes(
                &mut self.common,
                symbol_db,
                output_sections,
                symbol_resolution_flags,
            )?;
        }
        self.common.validate_sizes()?;
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution>>,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<GroupLayout<'data>> {
        let eh_frame_start_address = *memory_offsets.get(part_id::EH_FRAME);
        let mut files = self
            .files
            .into_iter()
            .map(|file| file.finalise_layout(memory_offsets, resolutions_out, resources))
            .collect::<Result<Vec<_>>>()?;
        let strtab_start_offset = self
            .common
            .finalise_layout(memory_offsets, resources.section_layouts);
        let dynstr_start_offset = (memory_offsets.get(part_id::DYNSTR)
            - resources
                .section_layouts
                .get(output_section_id::DYNSTR)
                .mem_offset) as u32;
        memory_offsets.increment(part_id::DYNSTR, *self.common.mem_sizes.get(part_id::DYNSTR));

        set_last_verneed(&self.common, resources, memory_offsets, &mut files);

        Ok(GroupLayout {
            files,
            strtab_start_offset,
            dynstr_start_offset,
            file_sizes: compute_file_sizes(&self.common.mem_sizes, resources.output_sections),
            mem_sizes: self.common.mem_sizes,
            eh_frame_start_address,
        })
    }
}

/// Determines if the sizes from `common` indicate that we're working with the last group that
/// contributes to .gnu.version_r. If we are, then finds the last dynamic object in the group that
/// has verdef_info and lets it know that it's the last verneed. This is needed when we write so
/// that we know whether to output the offset to the next verneed, or zero for the last record.
fn set_last_verneed(
    common: &CommonGroupState,
    resources: &FinaliseLayoutResources,
    memory_offsets: &OutputSectionPartMap<u64>,
    files: &mut [FileLayout],
) {
    let gnu_version_r_layout = resources
        .section_layouts
        .get(output_section_id::GNU_VERSION_R);
    let is_last_verneed = *common.mem_sizes.get(part_id::GNU_VERSION_R) > 0
        && (*memory_offsets.get(part_id::GNU_VERSION_R)
            == gnu_version_r_layout.mem_offset + gnu_version_r_layout.mem_size);
    if is_last_verneed {
        for file in files.iter_mut().rev() {
            if let FileLayout::Dynamic(d) = file
                && d.verneed_info.is_some()
            {
                d.is_last_verneed = true;
                break;
            }
        }
    }
}

fn activate<'data, A: Arch>(
    common: &mut CommonGroupState<'data>,
    file: &mut FileLayoutState<'data>,
    queue: &mut LocalWorkQueue,
    resources: &GraphResources<'data, '_>,
) -> Result {
    match file {
        FileLayoutState::Object(s) => s.activate::<A>(common, resources, queue)?,
        FileLayoutState::Prelude(s) => s.activate(common, resources, queue)?,
        FileLayoutState::Dynamic(s) => s.activate(common, resources, queue)?,
        FileLayoutState::LinkerScript(s) => s.activate(common, resources)?,
        FileLayoutState::NotLoaded(_) => {}
        FileLayoutState::Epilogue(s) => s.activate(resources, queue),
    }
    Ok(())
}

impl LocalWorkQueue {
    #[inline(always)]
    fn send_work(&mut self, resources: &GraphResources, file_id: FileId, work: WorkItem) {
        if file_id.group() == self.index {
            self.local_work.push(work);
        } else {
            resources.send_work(file_id, work);
        }
    }

    fn new(index: usize) -> LocalWorkQueue {
        Self {
            index,
            local_work: Default::default(),
        }
    }

    #[inline(always)]
    fn send_symbol_request(&mut self, symbol_id: SymbolId, resources: &GraphResources) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work(
            resources,
            symbol_file_id,
            WorkItem::LoadGlobalSymbol(symbol_id),
        );
    }

    fn send_copy_relocation_request(&mut self, symbol_id: SymbolId, resources: &GraphResources) {
        debug_assert!(resources.symbol_db.is_canonical(symbol_id));
        let symbol_file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        self.send_work(
            resources,
            symbol_file_id,
            WorkItem::CopyRelocateSymbol(symbol_id),
        );
    }
}

impl GraphResources<'_, '_> {
    fn report_error(&self, error: Error) {
        self.errors.lock().unwrap().push(error);
    }

    /// Sends all work in `work` to the worker for `file_id`. Leaves `work` empty so that it can be
    /// reused.
    #[inline(always)]
    fn send_work(&self, file_id: FileId, work: WorkItem) {
        let worker;
        {
            let mut slot = self.worker_slots[file_id.group()].lock().unwrap();
            worker = slot.worker.take();
            slot.work.push(work);
        };
        if let Some(worker) = worker {
            // The capacity of `waiting_workers` is equal to the total number of workers, so the
            // following should never fail.
            let _ = self.waiting_workers.push(worker);
            // If there's an idle thread, wake it so that it can process the work.
            if let Some(thread) = self
                .idle_threads
                .as_ref()
                .and_then(|idle_threads| idle_threads.pop())
            {
                thread.unpark();
            }
        }
    }

    fn shut_down(&self) {
        self.done.store(true, atomic::Ordering::SeqCst);
        // Wake up all sleeping threads so that they can shut down.
        if let Some(idle_threads) = self.idle_threads.as_ref() {
            while let Some(thread) = idle_threads.pop() {
                thread.unpark();
            }
        }
    }
}

impl<'data> FileLayoutState<'data> {
    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_db: &SymbolDb<'data>,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        match self {
            FileLayoutState::Object(s) => {
                s.finalise_sizes(common, symbol_db, output_sections, symbol_resolution_flags);
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Dynamic(s) => {
                s.finalise_sizes(common)?;
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Prelude(s) => {
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::Epilogue(s) => {
                s.finalise_sizes(common, symbol_db, symbol_resolution_flags)?;
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::LinkerScript(s) => {
                s.finalise_sizes(common, symbol_db, symbol_resolution_flags)?;
                s.finalise_symbol_sizes(common, symbol_db, symbol_resolution_flags)?;
            }
            FileLayoutState::NotLoaded(_) => {}
        }
        Ok(())
    }

    fn do_work<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        work_item: WorkItem,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match work_item {
            WorkItem::LoadGlobalSymbol(symbol_id) => self
                .handle_symbol_request::<A>(common, symbol_id, resources, queue)
                .with_context(|| {
                    format!(
                        "Failed to load {} from {self}",
                        resources.symbol_db.symbol_debug(symbol_id),
                    )
                }),
            WorkItem::CopyRelocateSymbol(symbol_id) => match self {
                FileLayoutState::Dynamic(state) => state.copy_relocate_symbol(symbol_id, resources),

                _ => {
                    bail!(
                        "Internal error: ExportCopyRelocation sent to non-dynamic object for: {}",
                        resources.symbol_db.symbol_debug(symbol_id)
                    )
                }
            },
            WorkItem::LoadSection(request) => match self {
                FileLayoutState::Object(object_layout_state) => object_layout_state
                    .handle_section_load_request::<A>(
                        common,
                        resources,
                        queue,
                        request.section_index(),
                    ),
                _ => bail!("Request to load section from non-object: {self}"),
            },
            WorkItem::ExportDynamic(symbol_id) => match self {
                FileLayoutState::Object(object) => {
                    object.export_dynamic::<A>(common, symbol_id, resources, queue)
                }
                _ => {
                    // Non-loaded and dynamic objects don't do anything in response to a request to
                    // export a dynamic symbol.
                    Ok(())
                }
            },
        }
    }

    fn handle_symbol_request<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        match self {
            FileLayoutState::Object(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
            FileLayoutState::Prelude(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
            FileLayoutState::Dynamic(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
            FileLayoutState::LinkerScript(_) => {}
            FileLayoutState::NotLoaded(_) => {}
            FileLayoutState::Epilogue(state) => {
                state.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }
        }
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut sharded_vec_writer::Shard<Option<Resolution>>,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<FileLayout<'data>> {
        let resolutions_out = &mut ResolutionWriter { resolutions_out };
        let file_layout = match self {
            Self::Object(s) => {
                let _span = tracing::debug_span!(
                    "finalise_layout",
                    file = %s.input
                )
                .entered();
                FileLayout::Object(s.finalise_layout(memory_offsets, resolutions_out, resources)?)
            }
            Self::Prelude(s) => FileLayout::Prelude(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
            Self::Epilogue(s) => FileLayout::Epilogue(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
            Self::Dynamic(s) => FileLayout::Dynamic(s.finalise_layout(
                memory_offsets,
                resolutions_out,
                resources,
            )?),
            Self::LinkerScript(s) => {
                s.finalise_layout(memory_offsets, resolutions_out, resources)?;
                FileLayout::LinkerScript(s)
            }
            Self::NotLoaded(s) => {
                for _ in 0..s.symbol_id_range.len() {
                    resolutions_out.write(None)?;
                }
                FileLayout::NotLoaded
            }
        };
        Ok(file_layout)
    }
}

fn compute_file_sizes(
    mem_sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections<'_>,
) -> OutputSectionPartMap<usize> {
    mem_sizes.map(|part_id, size| {
        if output_sections.has_data_in_file(part_id.output_section_id()) {
            *size as usize
        } else {
            0
        }
    })
}

impl std::fmt::Display for PreludeLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<prelude>", f)
    }
}

impl std::fmt::Display for EpilogueLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt("<epilogue>", f)
    }
}

impl std::fmt::Display for LinkerScriptLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)
    }
}

impl std::fmt::Display for FileLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Dynamic(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::LinkerScript(s) => std::fmt::Display::fmt(s, f),
            FileLayoutState::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            FileLayoutState::NotLoaded(_) => std::fmt::Display::fmt("<not-loaded>", f),
            FileLayoutState::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
        }
    }
}

impl std::fmt::Display for FileLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Object(s) => std::fmt::Display::fmt(s, f),
            Self::Dynamic(s) => std::fmt::Display::fmt(s, f),
            Self::LinkerScript(s) => std::fmt::Display::fmt(s, f),
            Self::Prelude(_) => std::fmt::Display::fmt("<prelude>", f),
            Self::Epilogue(_) => std::fmt::Display::fmt("<epilogue>", f),
            Self::NotLoaded => std::fmt::Display::fmt("<not loaded>", f),
        }
    }
}

impl std::fmt::Display for GroupLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.files.len() == 1 {
            self.files[0].fmt(f)
        } else {
            write!(
                f,
                "Group with {} files. Rerun with {}=1",
                self.files.len(),
                crate::args::FILES_PER_GROUP_ENV
            )
        }
    }
}

impl std::fmt::Display for GroupState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.files.len() == 1 {
            self.files[0].fmt(f)
        } else {
            write!(
                f,
                "Group with {} files. Rerun with {}=1",
                self.files.len(),
                crate::args::FILES_PER_GROUP_ENV
            )
        }
    }
}

impl std::fmt::Debug for FileLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self, f)
    }
}

impl std::fmt::Display for ObjectLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id())
    }
}

impl std::fmt::Display for DynamicLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id())
    }
}

impl std::fmt::Display for DynamicLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        write!(f, " ({})", self.file_id)
    }
}

impl std::fmt::Display for ObjectLayout<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.input, f)?;
        // TODO: This is mostly for debugging use. Consider only showing this if some environment
        // variable is set, or only in debug builds.
        write!(f, " ({})", self.file_id)
    }
}

impl Section {
    fn create(
        header: &crate::elf::SectionHeader,
        object_state: &mut ObjectLayoutState,
        section_index: object::SectionIndex,
        part_id: PartId,
    ) -> Result<Section> {
        let size = object_state.object.section_size(header)?;
        let section = Section {
            index: section_index,
            part_id,
            size,
            resolution_flags: ResolutionFlags::empty(),
            is_writable: SectionFlags::from_header(header).contains(shf::WRITE),
        };
        Ok(section)
    }

    // How much space we take up. This is our size rounded up to the next multiple of our alignment,
    // unless we're in a packed section, in which case it's just our size.
    pub(crate) fn capacity(&self) -> u64 {
        if self.part_id.should_pack() {
            self.size
        } else {
            self.alignment().align_up(self.size)
        }
    }

    pub(crate) fn output_section_id(&self) -> OutputSectionId {
        self.part_id.output_section_id()
    }

    pub(crate) fn output_part_id(&self) -> PartId {
        self.part_id
    }

    /// Returns the alignment for this section.
    fn alignment(&self) -> Alignment {
        self.part_id.alignment()
    }
}

#[inline(always)]
fn process_relocation<A: Arch>(
    object: &ObjectLayoutState,
    common: &mut CommonGroupState,
    rel: &Crel,
    section: &object::elf::SectionHeader64<LittleEndian>,
    resources: &GraphResources,
    queue: &mut LocalWorkQueue,
    is_debug_section: bool,
) -> Result<RelocationModifier> {
    let args = resources.symbol_db.args;
    let mut next_modifier = RelocationModifier::Normal;
    if let Some(local_sym_index) = rel.symbol() {
        let symbol_db = resources.symbol_db;
        let symbol_id = symbol_db.definition(object.symbol_id_range.input_to_id(local_sym_index));
        let symbol_value_flags = symbol_db.local_symbol_value_flags(symbol_id);
        let rel_offset = rel.r_offset;
        let r_type = rel.r_type;

        let rel_info = if let Some(relaxation) = A::Relaxation::new(
            r_type,
            object.object.raw_section_data(section)?,
            rel_offset,
            symbol_value_flags,
            args.output_kind(),
            SectionFlags::from_header(section),
            true,
        )
        .filter(|relaxation| args.relax || relaxation.is_mandatory())
        {
            next_modifier = relaxation.next_modifier();
            relaxation.rel_info()
        } else {
            A::relocation_from_raw(r_type)?
        };

        let section_is_writable = SectionFlags::from_header(section).contains(shf::WRITE);
        let mut resolution_flags = resolution_flags(rel_info.kind);

        if rel_info.kind.is_tls() {
            if does_relocation_require_static_tls(rel_info.kind) {
                resources
                    .has_static_tls
                    .store(true, atomic::Ordering::Relaxed);
            }

            if needs_tlsld(rel_info.kind) && !resources.uses_tlsld.load(atomic::Ordering::Relaxed) {
                resources.uses_tlsld.store(true, atomic::Ordering::Relaxed);
            }
        } else if resolution_flags.needs_direct() && symbol_value_flags.is_interposable() {
            if section_is_writable {
                common.allocate(part_id::RELA_DYN_GENERAL, elf::RELA_ENTRY_SIZE);
            } else if symbol_value_flags.is_function() {
                resolution_flags.remove(ResolutionFlags::DIRECT);
                resolution_flags |= ResolutionFlags::PLT | ResolutionFlags::GOT;
            } else if !symbol_value_flags.is_absolute() {
                if args.allow_copy_relocations {
                    resolution_flags |= ResolutionFlags::COPY_RELOCATION;
                } else {
                    // We don't at present support text relocations, so if we can't apply a copy
                    // relocation, we error instead.
                    bail!(
                        "Direct relocation ({}) to dynamic symbol from non-writable section, \
                        but copy relocations are disabled. {}",
                        A::rel_type_to_string(r_type),
                        symbol_db.symbol_debug(symbol_id),
                    );
                }
            }
        } else if args.is_relocatable()
            && rel_info.kind == RelocationKind::Absolute
            && (symbol_value_flags.is_address() | symbol_value_flags.is_ifunc())
        {
            if section_is_writable {
                common.allocate(part_id::RELA_DYN_RELATIVE, elf::RELA_ENTRY_SIZE);
            } else if !is_debug_section {
                bail!(
                    "Cannot apply relocation {} to read-only section. \
                    Please recompile with -fPIC or link with -no-pie",
                    A::rel_type_to_string(r_type),
                );
            }
        }

        let previous_flags =
            resources.symbol_resolution_flags[symbol_id.as_usize()].fetch_or(resolution_flags);

        if previous_flags.is_empty() {
            queue.send_symbol_request(symbol_id, resources);
            if should_emit_undefined_error(
                object.object.symbol(local_sym_index)?,
                object.file_id,
                symbol_db.file_id_for_symbol(symbol_id),
                symbol_value_flags,
                args,
            ) {
                let symbol_name = symbol_db.symbol_name_for_display(symbol_id);
                let source_info = crate::dwarf_address_info::get_source_info::<A>(
                    object.object,
                    &object.relocations,
                    section,
                    rel_offset,
                )
                .context("Failed to get source info")?;

                let lto_file = is_undefined_lto(resources, symbol_id);

                if let Some(file) = lto_file {
                    resources.report_error(error!(
                        "undefined reference to `{symbol_name}` found in LTO section of {}",
                        file.canonicalize()
                            .unwrap_or(PathBuf::new())
                            .file_name()
                            .expect("Canonicalized path can't have /.. at end")
                            .display()
                    ));
                } else if args.error_unresolved_symbols {
                    resources.report_error(error!(
                        "Undefined symbol {symbol_name}, referenced by {}\n    {}",
                        source_info, object.input,
                    ));
                } else {
                    crate::error::warning(&format!(
                        "Undefined symbol {symbol_name}, referenced by {}\n    {}",
                        source_info, object.input,
                    ));
                }
            }
        }

        if resolution_flags.needs_copy_relocation() && !previous_flags.needs_copy_relocation() {
            queue.send_copy_relocation_request(symbol_id, resources);
        }
    }
    Ok(next_modifier)
}

fn is_undefined_lto(resources: &GraphResources, symbol_id: SymbolId) -> Option<PathBuf> {
    let raw_symbol_name = resources
        .symbol_db
        .symbol_name(symbol_id)
        .unwrap_or_else(|_| panic!("Found symbol display so symbol with id {symbol_id} exists"));
    resources
        .symbol_db
        .groups
        .iter()
        .find_map(|group| match group {
            Group::Objects(data) => data.iter().find_map(|input| {
                let section_table = input.parsed.object.sections;
                let file = &input.parsed.object;
                section_table
                    .iter()
                    .filter(|section_header| {
                        section_table
                            .section_name(LittleEndian, section_header)
                            .unwrap_or(&[])
                            .starts_with(secnames::GNU_LTO_SYMTAB_PREFIX.as_bytes())
                    })
                    .find_map(|section_header| {
                        let lto_contains_undef = file
                            .section_data_cow(section_header)
                            .unwrap_or_default()
                            .split(|datum| *datum == 0)
                            .any(|symbol| symbol == raw_symbol_name.bytes());
                        if lto_contains_undef {
                            return Some(input.parsed.input.file.filename.clone());
                        }
                        None
                    })
            }),
            _ => None,
        })
}

/// Returns whether the supplied relocation type requires static TLS. If true and we're writing a
/// shared object, then the STATIC_TLS will be set in the shared object which is a signal to the
/// runtime loader that the shared object cannot be loaded at runtime (e.g. with dlopen).
fn does_relocation_require_static_tls(rel_kind: RelocationKind) -> bool {
    resolution_flags(rel_kind) == ResolutionFlags::GOT_TLS_OFFSET
}

fn resolution_flags(rel_kind: RelocationKind) -> ResolutionFlags {
    match rel_kind {
        RelocationKind::PltRelative | RelocationKind::PltRelGotBase => {
            ResolutionFlags::PLT | ResolutionFlags::GOT
        }
        RelocationKind::Got | RelocationKind::GotRelGotBase | RelocationKind::GotRelative => {
            ResolutionFlags::GOT
        }
        RelocationKind::GotTpOff
        | RelocationKind::GotTpOffGot
        | RelocationKind::GotTpOffGotBase => ResolutionFlags::GOT_TLS_OFFSET,
        RelocationKind::TlsGd | RelocationKind::TlsGdGot | RelocationKind::TlsGdGotBase => {
            ResolutionFlags::GOT_TLS_MODULE
        }
        RelocationKind::TlsDesc
        | RelocationKind::TlsDescGot
        | RelocationKind::TlsDescGotBase
        | RelocationKind::TlsDescCall => ResolutionFlags::GOT_TLS_DESCRIPTOR,
        RelocationKind::TlsLd | RelocationKind::TlsLdGot | RelocationKind::TlsLdGotBase => {
            ResolutionFlags::empty()
        }
        RelocationKind::Absolute
        | RelocationKind::AbsoluteSet
        | RelocationKind::AbsoluteSetWord6
        | RelocationKind::AbsoluteAddition
        | RelocationKind::AbsoluteSubtraction
        | RelocationKind::AbsoluteSubtractionWord6
        | RelocationKind::Relative
        | RelocationKind::RelativeRiscVLow12
        | RelocationKind::DtpOff
        | RelocationKind::TpOff
        | RelocationKind::SymRelGotBase
        | RelocationKind::PairSubtraction => ResolutionFlags::DIRECT,
        RelocationKind::None | RelocationKind::AbsoluteAArch64 | RelocationKind::Alignment => {
            ResolutionFlags::empty()
        }
    }
}

impl<'data> PreludeLayoutState<'data> {
    fn new(input_state: resolution::ResolvedPrelude<'data>) -> Self {
        Self {
            file_id: PRELUDE_FILE_ID,
            symbol_id_range: SymbolIdRange::prelude(input_state.symbol_definitions.len()),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.symbol_definitions,
                start_symbol_id: SymbolId::zero(),
            },
            entry_symbol_id: None,
            needs_tlsld_got_entry: false,
            identity: crate::identity::linker_identity(),
            header_info: None,
            dynamic_linker: None,
            shstrtab_size: 0,
            eflags: 0,
        }
    }

    fn activate(
        &mut self,
        common: &mut CommonGroupState,
        resources: &GraphResources,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        resources.merged_strings.for_each(|section_id, merged| {
            if merged.len() > 0 {
                common.allocate(
                    section_id.part_id_with_alignment(alignment::MIN),
                    merged.len(),
                );
            }
        });

        // Allocate space to store the identity of the linker in the .comment section.
        common.allocate(
            output_section_id::COMMENT.part_id_with_alignment(alignment::MIN),
            self.identity.len() as u64,
        );

        // The first entry in the symbol table must be null. Similarly, the first string in the
        // strings table must be empty.
        if !resources.symbol_db.args.strip_all {
            common.allocate(part_id::SYMTAB_LOCAL, size_of::<elf::SymtabEntry>() as u64);
            common.allocate(part_id::STRTAB, 1);
        }

        self.load_entry_point(resources, queue);

        if resources.symbol_db.args.needs_dynsym() {
            // Allocate space for the null symbol.
            common.allocate(part_id::DYNSTR, 1);
            common.allocate(part_id::DYNSYM, size_of::<elf::SymtabEntry>() as u64);
        }

        self.dynamic_linker = resources
            .symbol_db
            .args
            .dynamic_linker
            .as_ref()
            .map(|p| CString::new(p.as_os_str().as_encoded_bytes()))
            .transpose()?;
        if let Some(dynamic_linker) = self.dynamic_linker.as_ref() {
            common.allocate(
                part_id::INTERP,
                dynamic_linker.as_bytes_with_nul().len() as u64,
            );
        }

        Ok(())
    }

    fn load_entry_point(&mut self, resources: &GraphResources, queue: &mut LocalWorkQueue) {
        let Some(symbol_id) =
            resources
                .symbol_db
                .get_unversioned(&UnversionedSymbolName::prehashed(
                    resources.symbol_db.entry_symbol_name(),
                ))
        else {
            // We'll emit a warning when writing the file if it's an executable.
            return;
        };

        self.entry_symbol_id = Some(symbol_id);
        let file_id = resources.symbol_db.file_id_for_symbol(symbol_id);
        let old_flags = resources.symbol_resolution_flags[symbol_id.as_usize()]
            .fetch_or(ResolutionFlags::DIRECT);
        if old_flags.is_empty() {
            queue.send_work(resources, file_id, WorkItem::LoadGlobalSymbol(symbol_id));
        }
    }

    fn pre_finalise_sizes(
        &mut self,
        common: &mut CommonGroupState,
        uses_tlsld: &AtomicBool,
        args: &Args,
    ) {
        if uses_tlsld.load(atomic::Ordering::Relaxed) {
            // Allocate space for a TLS module number and offset for use with TLSLD relocations.
            common.allocate(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
            self.needs_tlsld_got_entry = true;
            // For shared objects, we'll need to use a DTPMOD relocation to fill in the TLS module
            // number.
            if !args.output_kind().is_executable() {
                common.allocate(part_id::RELA_DYN_GENERAL, crate::elf::RELA_ENTRY_SIZE);
            }
        }

        if args.should_write_eh_frame_hdr {
            common.allocate(part_id::EH_FRAME_HDR, size_of::<elf::EhFrameHdr>() as u64);
        }
    }

    /// This function is where we determine sizes that depend on other sizes. For example, the size
    /// of the section headers table, which depends on which sections we're writing, which depends
    /// on which sections are non-empty. We also decide which internal symtab entries we'll write
    /// here, since that also depends on which sections we're writing.
    fn apply_late_size_adjustments(
        &mut self,
        common: &mut CommonGroupState,
        total_sizes: &mut OutputSectionPartMap<u64>,
        sections_with_content: OutputSectionMap<bool>,
        output_sections: &mut OutputSections,
        output_order: &OutputOrder,
        program_segments: &ProgramSegments,
        symbol_resolution_flags: &mut [ResolutionFlags],
        symbol_db: &SymbolDb,
    ) -> Result {
        // Total section  sizes have already been computed. So any allocations we do need to update
        // both `total_sizes` and the size records in `common`. We track the extra sizes in
        // `extra_sizes` which we can then later add to both.
        let mut extra_sizes = OutputSectionPartMap::with_size(common.mem_sizes.num_parts());

        self.determine_header_sizes(
            total_sizes,
            &mut extra_sizes,
            sections_with_content,
            output_sections,
            program_segments,
            output_order,
            symbol_resolution_flags,
            symbol_db,
        );

        self.allocate_symbol_table_sizes(
            output_sections,
            symbol_resolution_flags,
            symbol_db,
            &mut extra_sizes,
        )?;

        // We need to allocate both our own size record and the group totals, since they've already
        // been computed.
        common.mem_sizes.merge(&extra_sizes);
        total_sizes.merge(&extra_sizes);

        Ok(())
    }

    /// Allocates space for our internal symbols. For unreferenced symbols, we also update the
    /// symbol so that it is treated as referenced, but only for symbols in sections that we're
    /// going to emit.
    fn allocate_symbol_table_sizes(
        &self,
        output_sections: &OutputSections,
        symbol_resolution_flags: &mut [ResolutionFlags],
        symbol_db: &SymbolDb<'_>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
    ) -> Result<(), Error> {
        if symbol_db.args.strip_all {
            return Ok(());
        }

        self.internal_symbols.allocate_symbol_table_sizes(
            extra_sizes,
            symbol_db,
            |symbol_id, def_info| {
                let resolution_flags = &mut symbol_resolution_flags[symbol_id.as_usize()];

                // If the symbol is referenced, then we keep it.
                if !resolution_flags.is_empty() {
                    return true;
                }

                // We always emit symbols that the user requested be undefined.
                let mut should_emit = def_info.placement == SymbolPlacement::ForceUndefined;

                // Keep the symbol if we're going to write the section, even though the symbol isn't
                // referenced. It can be useful to have symbols like _GLOBAL_OFFSET_TABLE_ when
                // using a debugger.
                should_emit |= def_info.section_id().is_some_and(|output_section_id| {
                    output_sections.will_emit_section(output_section_id)
                });

                if should_emit {
                    // Mark the symbol as referenced so that we later generate a resolution for
                    // it and subsequently write it to the symbol table.
                    *resolution_flags |= ResolutionFlags::DIRECT;
                }

                should_emit
            },
        )
    }

    fn determine_header_sizes(
        &mut self,
        total_sizes: &OutputSectionPartMap<u64>,
        extra_sizes: &mut OutputSectionPartMap<u64>,
        sections_with_content: OutputSectionMap<bool>,
        output_sections: &mut OutputSections,
        program_segments: &ProgramSegments,
        output_order: &OutputOrder,
        symbol_resolution_flags: &[ResolutionFlags],
        symbol_db: &SymbolDb,
    ) {
        use output_section_id::OrderEvent;

        // Determine which sections to keep. To start with, we keep all sections into which we've
        // loaded an input section. Note, this includes where the input section and even the output
        // section is empty. We still need the output section as it may contain symbols.
        let mut keep_sections = sections_with_content;

        // Next, keep any sections for which we've recorded a non-zero size, even if we didn't
        // record the loading of an input section. This covers sections where we generate content.
        total_sizes.map(|part_id, size| {
            if *size > 0 {
                *keep_sections.get_mut(part_id.output_section_id()) = true;
            }
        });

        // Keep any sections that we've said we want to keep regardless.
        for section_id in output_section_id::built_in_section_ids() {
            if section_id.built_in_details().keep_if_empty {
                *keep_sections.get_mut(section_id) = true;
            }
        }

        // Keep any sections that have a start/stop symbol which is referenced.
        symbol_resolution_flags[self.symbol_id_range().as_usize()]
            .iter()
            .zip(self.internal_symbols.symbol_definitions.iter())
            .for_each(|(symbol_state, definition)| {
                if !symbol_state.is_empty()
                    && let Some(section_id) = definition.section_id()
                {
                    *keep_sections.get_mut(section_id) = true;
                }
            });

        for i in 0..output_sections.num_sections() {
            let section_id = OutputSectionId::from_usize(i);

            // If any secondary sections were marked to be kept, then unmark them and mark the
            // primary instead.
            if let Some(primary_id) = output_sections.merge_target(section_id) {
                let keep_secondary = replace(keep_sections.get_mut(section_id), false);
                *keep_sections.get_mut(primary_id) |= keep_secondary;
            }

            // Remove any sections without a type except for section 0 (the file header). This
            // should just be the .phdr and .shdr sections which contain the program headers and
            // section headers. We need these sections in order to allocate space for those
            // structures, but other linkers don't emit section headers for them, so neither should
            // we.
            let section_info = output_sections.section_infos.get(section_id);
            if section_info.ty == sht::NULL && section_id != output_section_id::FILE_HEADER {
                *keep_sections.get_mut(section_id) = false;
            }
        }

        let num_sections = keep_sections.values_iter().filter(|p| **p).count();

        // Compute output indexes of each section.
        let mut next_output_index = 0;
        let mut output_section_indexes = vec![None; output_sections.num_sections()];
        for event in output_order {
            if let OrderEvent::Section(id) = event
                && *keep_sections.get(id)
            {
                debug_assert!(
                    output_sections.merge_target(id).is_none(),
                    "Tried to allocate section header for secondary section {}",
                    output_sections.section_debug(id)
                );
                output_section_indexes[id.as_usize()] = Some(next_output_index);
                next_output_index += 1;
            };
        }
        output_sections.output_section_indexes = output_section_indexes;

        // Determine which program segments contain sections that we're keeping.
        let mut keep_segments = program_segments
            .iter()
            .map(|details| details.always_keep())
            .collect_vec();
        let mut active_segments = Vec::with_capacity(4);
        for event in output_order {
            match event {
                OrderEvent::SegmentStart(segment_id) => active_segments.push(segment_id),
                OrderEvent::SegmentEnd(segment_id) => active_segments.retain(|a| *a != segment_id),
                OrderEvent::Section(section_id) => {
                    if *keep_sections.get(section_id) {
                        for segment_id in &active_segments {
                            keep_segments[segment_id.as_usize()] = true;
                        }
                        active_segments.clear();
                    }
                }
                OrderEvent::SetLocation(_) => {}
            }
        }

        // Always keep the program headers segment even though we don't emit any sections in it.
        keep_segments[0] = true;

        // If relro is disabled, then discard the relro segment.
        if !symbol_db.args.relro {
            for (segment_def, keep) in program_segments.into_iter().zip(keep_segments.iter_mut()) {
                if segment_def.segment_type == pt::GNU_RELRO {
                    *keep = false;
                }
            }
        }

        let active_segment_ids = (0..program_segments.len())
            .map(ProgramSegmentId::new)
            .filter(|id| keep_segments[id.as_usize()] || program_segments.is_stack_segment(*id))
            .collect();

        let header_info = HeaderInfo {
            num_output_sections_with_content: num_sections
                .try_into()
                .expect("output section count must fit in a u16"),

            active_segment_ids,
            eflags: self.eflags,
        };

        // Allocate space for headers based on segment and section counts.
        extra_sizes.increment(part_id::FILE_HEADER, u64::from(elf::FILE_HEADER_SIZE));
        extra_sizes.increment(part_id::PROGRAM_HEADERS, header_info.program_headers_size());
        extra_sizes.increment(part_id::SECTION_HEADERS, header_info.section_headers_size());
        self.shstrtab_size = output_sections
            .ids_with_info()
            .filter(|(id, _info)| output_sections.output_index_of_section(*id).is_some())
            .map(|(_id, info)| {
                if let SectionKind::Primary(name) = info.kind {
                    name.len() as u64 + 1
                } else {
                    0
                }
            })
            .sum::<u64>();
        extra_sizes.increment(part_id::SHSTRTAB, self.shstrtab_size);

        self.header_info = Some(header_info);
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, '_>,
    ) -> Result<PreludeLayout<'data>> {
        let header_layout = resources
            .section_layouts
            .get(output_section_id::FILE_HEADER);
        assert_eq!(header_layout.file_offset, 0);

        let tlsld_got_entry = self.needs_tlsld_got_entry.then(|| {
            let address = NonZeroU64::new(*memory_offsets.get(part_id::GOT))
                .expect("GOT address must never be zero");
            memory_offsets.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * 2);
            address
        });

        // Take the null symbol's index.
        if resources.symbol_db.args.needs_dynsym() {
            take_dynsym_index(memory_offsets, resources.section_layouts)?;
        }

        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

        memory_offsets.increment(
            output_section_id::COMMENT.part_id_with_alignment(alignment::MIN),
            self.identity.len() as u64,
        );
        resources.merged_strings.for_each(|section_id, merged| {
            if merged.len() > 0 {
                memory_offsets.increment(
                    section_id.part_id_with_alignment(alignment::MIN),
                    merged.len(),
                );
            }
        });

        Ok(PreludeLayout {
            internal_symbols: self.internal_symbols,
            entry_symbol_id: self.entry_symbol_id,
            tlsld_got_entry,
            identity: self.identity,
            dynamic_linker: self.dynamic_linker,
            header_info: self
                .header_info
                .expect("we should have computed header info by now"),
        })
    }
}

impl<'data> InternalSymbols<'data> {
    fn allocate_symbol_table_sizes(
        &self,
        sizes: &mut OutputSectionPartMap<u64>,
        symbol_db: &SymbolDb<'_>,
        mut should_keep_symbol: impl FnMut(SymbolId, &InternalSymDefInfo) -> bool,
    ) -> Result {
        // Allocate space in the symbol table for the symbols that we define.
        for (index, def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(index);
            if !symbol_db.is_canonical(symbol_id) || symbol_id.is_undefined() {
                continue;
            }

            if !should_keep_symbol(symbol_id, def_info) {
                continue;
            }

            sizes.increment(part_id::SYMTAB_GLOBAL, size_of::<elf::SymtabEntry>() as u64);
            let symbol_name = symbol_db.symbol_name(symbol_id)?;
            let symbol_name = RawSymbolName::parse(symbol_name.bytes()).name;
            sizes.increment(part_id::STRTAB, symbol_name.len() as u64 + 1);
        }
        Ok(())
    }

    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources,
    ) -> Result {
        // Define symbols that are optionally put at the start/end of some sections.
        let emitter = create_global_address_emitter(resources.symbol_resolution_flags);
        for (local_index, &def_info) in self.symbol_definitions.iter().enumerate() {
            let symbol_id = self.start_symbol_id.add_usize(local_index);

            let resolution = create_start_end_symbol_resolution(
                memory_offsets,
                resources,
                &emitter,
                def_info,
                symbol_id,
            );

            resolutions_out.write(resolution)?;
        }
        Ok(())
    }

    pub(crate) fn symbol_id_range(&self) -> SymbolIdRange {
        SymbolIdRange::epilogue(self.start_symbol_id, self.symbol_definitions.len())
    }
}

fn create_start_end_symbol_resolution(
    memory_offsets: &mut OutputSectionPartMap<u64>,
    resources: &FinaliseLayoutResources<'_, '_>,
    emitter: &GlobalAddressEmitter<'_>,
    def_info: InternalSymDefInfo,
    symbol_id: SymbolId,
) -> Option<Resolution> {
    if !resources.symbol_db.is_canonical(symbol_id) {
        return None;
    }

    if resources.symbol_resolution_flags[symbol_id.as_usize()].is_empty() {
        return None;
    }

    let raw_value = match def_info.placement {
        SymbolPlacement::Undefined | SymbolPlacement::ForceUndefined => 0,
        SymbolPlacement::SectionStart(section_id) => {
            resources.section_layouts.get(section_id).mem_offset
        }

        SymbolPlacement::SectionEnd(section_id) => {
            let sec = resources.section_layouts.get(section_id);
            sec.mem_offset + sec.mem_size
        }
    };

    Some(create_resolution(
        emitter.symbol_resolution_flags[symbol_id.as_usize()],
        raw_value,
        None,
        resources.symbol_db.symbol_value_flags(symbol_id),
        memory_offsets,
    ))
}

fn should_emit_undefined_error(
    symbol: &Symbol,
    sym_file_id: FileId,
    sym_def_file_id: FileId,
    symbol_value_flags: ValueFlags,
    args: &Args,
) -> bool {
    if (args.output_kind() == OutputKind::SharedObject && !args.no_undefined) || symbol.is_weak() {
        return false;
    }

    let is_symbol_undefined = sym_file_id == sym_def_file_id
        && symbol.is_undefined(LittleEndian)
        && symbol_value_flags.is_absolute();

    match args.unresolved_symbols {
        crate::args::UnresolvedSymbols::IgnoreAll
        | crate::args::UnresolvedSymbols::IgnoreInObjectFiles => false,
        _ => is_symbol_undefined,
    }
}

impl<'data> EpilogueLayoutState<'data> {
    fn activate(&mut self, resources: &GraphResources<'data, '_>, _queue: &mut LocalWorkQueue) {
        self.build_id_size = match &resources.symbol_db.args.build_id {
            BuildIdOption::None => None,
            BuildIdOption::Fast => Some(size_of::<blake3::Hash>()),
            BuildIdOption::Hex(hex) => Some(hex.len()),
            BuildIdOption::Uuid => Some(size_of::<uuid::Uuid>()),
        };
    }

    fn new(input_state: ResolvedEpilogue<'data>) -> EpilogueLayoutState<'data> {
        EpilogueLayoutState {
            file_id: input_state.file_id,
            symbol_id_range: SymbolIdRange::epilogue(
                input_state.start_symbol_id,
                input_state.custom_start_stop_defs.len(),
            ),
            internal_symbols: InternalSymbols {
                symbol_definitions: input_state.custom_start_stop_defs,
                start_symbol_id: input_state.start_symbol_id,
            },
            dynamic_symbol_definitions: Default::default(),
            gnu_hash_layout: None,
            gnu_property_notes: Default::default(),
            build_id_size: Default::default(),
            verdefs: Default::default(),
            riscv_attributes: Default::default(),
        }
    }

    fn gnu_property_notes_section_size(&self) -> u64 {
        if self.gnu_property_notes.is_empty() {
            0
        } else {
            (size_of::<NoteHeader>()
                + GNU_NOTE_NAME.len()
                + self.gnu_property_notes.len() * GNU_NOTE_PROPERTY_ENTRY_SIZE) as u64
        }
    }

    fn riscv_attributes_section_size(&self) -> u64 {
        let size_of_uleb_encoded = |value| {
            let mut cursor = Cursor::new([0u8; 10]);
            leb128::write::unsigned(&mut cursor, value).unwrap()
        };

        (if self.riscv_attributes.is_empty() {
            0
        } else {
            1 // 'A'
            + 4 // sizeof(u32)
            + size_of_uleb_encoded(TAG_RISCV_WHOLE_FILE)
            + 4 // sizeof(u32)
            + RISCV_ATTRIBUTE_VENDOR_NAME.len() + 1
            + self.riscv_attributes.iter().map(|attr| {
                match attr {
                    RiscVAttribute::StackAlign(align) => {
                                        size_of_uleb_encoded(TAG_RISCV_STACK_ALIGN) +
                                        size_of_uleb_encoded(*align)
                                    }
                    RiscVAttribute::Arch(arch) => {
                                        size_of_uleb_encoded(TAG_RISCV_ARCH)
                                        +arch.to_attribute_string().len() + 1
                                    }
                    RiscVAttribute::UnalignedAccess(_) => {
                                        size_of_uleb_encoded(TAG_RISCV_UNALIGNED_ACCESS) + 1
                                    }
                    RiscVAttribute::PrivilegedSpecMajor(version) => {
                                        size_of_uleb_encoded(TAG_RISCV_PRIV_SPEC) +
                                        size_of_uleb_encoded(*version)
                    },
                    RiscVAttribute::PrivilegedSpecMinor(version) => {
                                        size_of_uleb_encoded(TAG_RISCV_PRIV_SPEC_MINOR) +
                                        size_of_uleb_encoded(*version)
                    }
                    RiscVAttribute::PrivilegedSpecRevision(version) => {
                                        size_of_uleb_encoded(TAG_RISCV_PRIV_SPEC_REVISION) +
                                        size_of_uleb_encoded(*version)
                    }
                                    }
            }).sum::<usize>()
        }) as u64
    }

    fn gnu_build_id_note_section_size(&self) -> Option<u64> {
        Some((size_of::<NoteHeader>() + GNU_NOTE_NAME.len() + self.build_id_size?) as u64)
    }

    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        if !symbol_db.args.strip_all {
            self.internal_symbols.allocate_symbol_table_sizes(
                &mut common.mem_sizes,
                symbol_db,
                |symbol_id, _| {
                    // For user-defined start/stop symbols, we only emit them if they're referenced.
                    !symbol_resolution_flags[symbol_id.as_usize()]
                        .get()
                        .is_empty()
                },
            )?;
        }

        if symbol_db.args.needs_dynamic() {
            let dynamic_entry_size = size_of::<crate::elf::DynamicEntry>();
            common.allocate(
                part_id::DYNAMIC,
                (elf_writer::NUM_EPILOGUE_DYNAMIC_ENTRIES * dynamic_entry_size) as u64,
            );
            if let Some(rpath) = symbol_db.args.rpath.as_ref() {
                common.allocate(part_id::DYNAMIC, dynamic_entry_size as u64);
                common.allocate(part_id::DYNSTR, rpath.len() as u64 + 1);
            }
            if let Some(soname) = symbol_db.args.soname.as_ref() {
                common.allocate(part_id::DYNSTR, soname.len() as u64 + 1);
                common.allocate(part_id::DYNAMIC, dynamic_entry_size as u64);
            }

            self.allocate_gnu_hash(common);

            common.allocate(
                part_id::DYNSTR,
                self.dynamic_symbol_definitions
                    .iter()
                    .map(|n| n.name.len() + 1)
                    .sum::<usize>() as u64,
            );
            common.allocate(
                part_id::DYNSYM,
                (self.dynamic_symbol_definitions.len() * size_of::<elf::SymtabEntry>()) as u64,
            );
        }

        common.allocate(
            part_id::NOTE_GNU_PROPERTY,
            self.gnu_property_notes_section_size(),
        );
        common.allocate(
            part_id::RISCV_ATTRIBUTES,
            self.riscv_attributes_section_size(),
        );

        if let Some(build_id_sec_size) = self.gnu_build_id_note_section_size() {
            common.allocate(part_id::NOTE_GNU_BUILD_ID, build_id_sec_size);
        }

        let version_count = symbol_db.version_script.version_count();
        if version_count > 0 {
            // If soname is not provided, allocate space for file name as the base version
            let base_version_name = if symbol_db.args.soname.is_none() {
                let file_name = symbol_db
                    .args
                    .output
                    .file_name()
                    .expect("File name should be present at this point")
                    .to_string_lossy()
                    .to_string();
                common.allocate(part_id::DYNSTR, file_name.len() as u64 + 1);
                file_name
            } else {
                String::new()
            };

            let mut verdefs = Vec::with_capacity(version_count.into());

            // Base version
            verdefs.push(VersionDef {
                name: base_version_name.into_bytes(),
                parent_index: None,
            });

            // Take all but the base version
            for version in symbol_db.version_script.version_iter().skip(1) {
                verdefs.push(VersionDef {
                    name: version.name.to_vec(),
                    parent_index: version.parent_index,
                });
                common.allocate(part_id::DYNSTR, version.name.len() as u64 + 1);
            }

            let dependencies_count = symbol_db.version_script.parent_count();
            common.allocate(
                part_id::GNU_VERSION_D,
                (size_of::<crate::elf::Verdef>() as u16 * version_count
                    + size_of::<crate::elf::Verdaux>() as u16
                        * (version_count + dependencies_count))
                    .into(),
            );
            self.verdefs.replace(verdefs);
        }

        Ok(())
    }

    /// Allocates space required for .gnu.hash. Also sorts dynamic symbol definitions by their hash
    /// bucket as required by .gnu.hash.
    fn allocate_gnu_hash(&mut self, common: &mut CommonGroupState) {
        // Our number of buckets is computed somewhat arbitrarily so that we have on average 2
        // symbols per bucket, but then we round up to a power of two.
        let num_defs = self.dynamic_symbol_definitions.len();
        let gnu_hash_layout = GnuHashLayout {
            bucket_count: (num_defs / 2).next_power_of_two() as u32,
            bloom_shift: 6,
            bloom_count: 1,
            // `symbol_base` is set later in `finalise_layout`.
            symbol_base: 0,
        };
        // Sort by bucket. Tie-break by name for determinism. We can use an unstable sort because
        // names should be unique. We use a parallel sort because we're processing symbols from
        // potentially many input objects, so there can be a lot.
        self.dynamic_symbol_definitions
            .par_sort_unstable_by_key(|d| (gnu_hash_layout.bucket_for_hash(d.hash), d.name));
        let num_blume = 1;
        common.allocate(
            part_id::GNU_HASH,
            (size_of::<elf::GnuHashHeader>()
                + size_of::<u64>() * num_blume
                + size_of::<u32>() * gnu_hash_layout.bucket_count as usize
                + size_of::<u32>() * num_defs) as u64,
        );
        self.gnu_hash_layout = Some(gnu_hash_layout);
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<EpilogueLayout<'data>> {
        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)?;

        let dynsym_start_index = ((memory_offsets.get(part_id::DYNSYM)
            - resources
                .section_layouts
                .get(output_section_id::DYNSYM)
                .mem_offset)
            / elf::SYMTAB_ENTRY_SIZE)
            .try_into()
            .context("Too many dynamic symbols")?;

        if let Some(gnu_hash_layout) = self.gnu_hash_layout.as_mut() {
            gnu_hash_layout.symbol_base = dynsym_start_index;
        }

        memory_offsets.increment(
            part_id::DYNSYM,
            self.dynamic_symbol_definitions.len() as u64 * elf::SYMTAB_ENTRY_SIZE,
        );

        memory_offsets.increment(
            part_id::NOTE_GNU_PROPERTY,
            self.gnu_property_notes_section_size(),
        );
        memory_offsets.increment(
            part_id::RISCV_ATTRIBUTES,
            self.riscv_attributes_section_size(),
        );

        if let Some(build_id_sec_size) = self.gnu_build_id_note_section_size() {
            memory_offsets.increment(part_id::NOTE_GNU_BUILD_ID, build_id_sec_size);
        }

        if let Some(verdefs) = &self.verdefs {
            memory_offsets.increment(
                part_id::GNU_VERSION_D,
                (size_of::<crate::elf::Verdef>() * verdefs.len()
                    + size_of::<crate::elf::Verdaux>()
                        * (verdefs.len()
                            + resources.symbol_db.version_script.parent_count() as usize))
                    as u64,
            );
        }

        let riscv_attributes_length = self.riscv_attributes_section_size() as u32;
        Ok(EpilogueLayout {
            internal_symbols: self.internal_symbols,
            gnu_hash_layout: self.gnu_hash_layout,
            dynamic_symbol_definitions: self.dynamic_symbol_definitions,
            dynsym_start_index,
            gnu_property_notes: self.gnu_property_notes,
            verdefs: self.verdefs,
            riscv_attributes: self.riscv_attributes,
            riscv_attributes_length,
        })
    }
}

pub(crate) struct HeaderInfo {
    pub(crate) num_output_sections_with_content: u16,
    pub(crate) active_segment_ids: Vec<ProgramSegmentId>,
    pub(crate) eflags: u32,
}

impl HeaderInfo {
    pub(crate) fn program_headers_size(&self) -> u64 {
        u64::from(elf::PROGRAM_HEADER_SIZE) * self.active_segment_ids.len() as u64
    }

    pub(crate) fn section_headers_size(&self) -> u64 {
        u64::from(elf::SECTION_HEADER_SIZE) * u64::from(self.num_output_sections_with_content)
    }
}

/// Construct a new inactive instance, which means we don't yet load non-GC sections and only
/// load them later if a symbol from this object is referenced.
fn new_object_layout_state(input_state: resolution::ResolvedObject) -> FileLayoutState {
    // Note, this function is called for all objects from a single thread, so don't be tempted to do
    // significant work here. Do work when activate is called instead. Doing it there also means
    // that we don't do the work unless the object is actually needed.

    if let Some(non_dynamic) = input_state.non_dynamic {
        FileLayoutState::Object(ObjectLayoutState {
            file_id: input_state.file_id,
            symbol_id_range: input_state.symbol_id_range,
            input: input_state.input,
            object: input_state.object,
            eh_frame_section: None,
            eh_frame_size: 0,
            sections: non_dynamic.sections,
            relocations: non_dynamic.relocations,
            cies: Default::default(),
            gnu_property_notes: Default::default(),
            riscv_attributes: Default::default(),
            exception_frames: Default::default(),
        })
    } else {
        FileLayoutState::Dynamic(DynamicLayoutState {
            file_id: input_state.file_id,
            symbol_id_range: input_state.symbol_id_range,
            lib_name: input_state.input.lib_name(),
            symbol_versions: input_state.object.versym,
            object: input_state.object,
            input: input_state.input,
            copy_relocations: Default::default(),

            // These fields are filled in properly when we activate.
            symbol_versions_needed: Default::default(),

            // These fields are filled in when we finalise sizes.
            verneed_info: None,
            non_addressable_indexes: Default::default(),
        })
    }
}

impl<'data> ObjectLayoutState<'data> {
    fn activate<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let mut eh_frame_section = None;
        let mut note_gnu_property_section = None;
        let mut riscv_attributes_section = None;

        let no_gc = !resources.symbol_db.args.gc_sections;

        for (i, section) in self.sections.iter().enumerate() {
            match section {
                SectionSlot::MustLoad(..)
                | SectionSlot::UnloadedDebugInfo(..)
                | SectionSlot::MergeStrings(_) => {
                    queue
                        .local_work
                        .push(WorkItem::LoadSection(SectionLoadRequest::new(
                            self.file_id,
                            object::SectionIndex(i),
                        )));
                }
                SectionSlot::Unloaded(sec) => {
                    if no_gc {
                        queue
                            .local_work
                            .push(WorkItem::LoadSection(SectionLoadRequest::new(
                                self.file_id,
                                object::SectionIndex(i),
                            )));
                    } else if sec.start_stop_eligible {
                        resources
                            .start_stop_sections
                            .get(sec.part_id.output_section_id())
                            .push(SectionLoadRequest {
                                file_id: self.file_id,
                                section_index: i as u32,
                            });
                    }
                }
                SectionSlot::EhFrameData(index) => {
                    eh_frame_section = Some(*index);
                }
                SectionSlot::NoteGnuProperty(index) => {
                    note_gnu_property_section = Some(*index);
                }
                SectionSlot::RiscvVAttributes(index) => {
                    riscv_attributes_section = Some(*index);
                }
                _ => (),
            }
        }

        if let Some(eh_frame_section_index) = eh_frame_section {
            process_eh_frame_data::<A>(
                self,
                common,
                self.symbol_id_range(),
                eh_frame_section_index,
                resources,
                queue,
            )?;
            let eh_frame_section = self.object.section(eh_frame_section_index)?;
            self.eh_frame_section = Some(eh_frame_section);
        }
        if let Some(note_gnu_property_index) = note_gnu_property_section {
            process_gnu_property_note(self, note_gnu_property_index)?;
        }
        if let Some(riscv_attributes_index) = riscv_attributes_section {
            ensure!(
                A::elf_header_arch_magic() == object::elf::EM_RISCV,
                ".riscv.attribute section is supported only for riscv64 target"
            );
            process_riscv_attributes(self, riscv_attributes_index)
                .context("Cannot parse .riscv.attributes section")?;
        }

        let export_all_dynamic = resources.symbol_db.args.output_kind() == OutputKind::SharedObject
            && (!resources.symbol_db.args.exclude_libs || !self.input.has_archive_semantics())
            || resources.symbol_db.args.needs_dynsym()
                && resources.symbol_db.args.export_all_dynamic_symbols;
        if export_all_dynamic
            || resources.symbol_db.args.needs_dynsym() && resources.symbol_db.export_list.is_some()
        {
            self.load_non_hidden_symbols::<A>(common, resources, queue, export_all_dynamic)?;
        }

        Ok(())
    }

    fn handle_section_load_request<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        section_index: SectionIndex,
    ) -> Result<(), Error> {
        match &self.sections[section_index.0] {
            SectionSlot::Unloaded(unloaded) | SectionSlot::MustLoad(unloaded) => {
                self.load_section::<A>(common, queue, *unloaded, section_index, resources)?;
            }
            SectionSlot::UnloadedDebugInfo(part_id) => {
                // On RISC-V, the debug info sections contain relocations to local symbols (e.g. labels).
                self.load_debug_section::<A>(common, queue, *part_id, section_index, resources)?;
            }
            SectionSlot::Discard => {
                bail!(
                    "{self}: Don't know what segment to put `{}` in, but it's referenced",
                    self.object.section_display_name(section_index),
                );
            }
            SectionSlot::Loaded(_)
            | SectionSlot::EhFrameData(..)
            | SectionSlot::LoadedDebugInfo(..)
            | SectionSlot::NoteGnuProperty(..)
            | SectionSlot::RiscvVAttributes(..) => {}
            SectionSlot::MergeStrings(sec) => {
                // We currently always load everything in merge-string sections. i.e. we don't GC
                // unreferenced data. So the only thing we need to do here is propagate section
                // flags.
                let header = self.object.section(section_index)?;
                common.store_section_attributes(sec.part_id, header);
            }
        };

        Ok(())
    }

    fn load_section<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,
        unloaded: UnloadedSection,
        section_index: SectionIndex,
        resources: &GraphResources<'data, 'scope>,
    ) -> Result {
        let part_id = unloaded.part_id;
        let header = self.object.section(section_index)?;
        let section = Section::create(header, self, section_index, part_id)?;

        match self.relocations(section.index)? {
            RelocationList::Rela(relocations) => {
                self.load_section_relocations::<A>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.crel_iter(),
                )?;
            }
            RelocationList::Crel(relocations) => {
                self.load_section_relocations::<A>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.flat_map(|r| r.ok()),
                )?;
            }
        }

        tracing::debug!(loaded_section = %self.object.section_display_name(section_index),);

        common.section_loaded(part_id, header, section);

        resources
            .sections_with_content
            .get(part_id.output_section_id())
            .fetch_or(true, atomic::Ordering::Relaxed);

        if section.size > 0 {
            self.process_section_exception_frames::<A>(
                unloaded.last_frame_index,
                common,
                resources,
                queue,
            )?;
        }

        self.sections[section_index.0] = SectionSlot::Loaded(section);

        Ok(())
    }

    fn load_section_relocations<A: Arch>(
        &self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,
        resources: &GraphResources<'data, '_>,
        section: Section,
        relocations: impl Iterator<Item = Crel>,
    ) -> Result {
        let mut modifier = RelocationModifier::Normal;
        for rel in relocations {
            if modifier == RelocationModifier::SkipNextRelocation {
                modifier = RelocationModifier::Normal;
                continue;
            }
            modifier = process_relocation::<A>(
                self,
                common,
                &rel,
                self.object.section(section.index)?,
                resources,
                queue,
                false,
            )
            .with_context(|| {
                format!(
                    "Failed to copy section {} from file {self}",
                    section_debug(self.object, section.index)
                )
            })?;
        }

        Ok(())
    }

    /// Processes the exception frames for a section that we're loading.
    fn process_section_exception_frames<A: Arch>(
        &mut self,
        frame_index: Option<FrameIndex>,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, '_>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let mut num_frames = 0;
        let mut next_frame_index = frame_index;
        while let Some(frame_index) = next_frame_index {
            let frame_data = &self.exception_frames[frame_index.as_usize()];
            next_frame_index = frame_data.previous_frame_for_section;

            self.eh_frame_size += u64::from(frame_data.frame_size);

            num_frames += 1;

            // Request loading of any sections/symbols referenced by the FDEs for our
            // section.
            if let Some(eh_frame_section) = self.eh_frame_section {
                match &frame_data.relocations {
                    DynamicRelocationSequence::Rela(frame_data_relocations) => {
                        for rel in *frame_data_relocations {
                            process_relocation::<A>(
                                self,
                                common,
                                &Crel::from_rela(rel, LittleEndian, false),
                                eh_frame_section,
                                resources,
                                queue,
                                false,
                            )?;
                        }
                    }
                    DynamicRelocationSequence::Crel(frame_data_relocations) => {
                        for rel in frame_data_relocations.crel_iter() {
                            process_relocation::<A>(
                                self,
                                common,
                                &rel,
                                eh_frame_section,
                                resources,
                                queue,
                                false,
                            )?;
                        }
                    }
                }
            }
        }

        if resources.symbol_db.args.should_write_eh_frame_hdr {
            common.allocate(
                part_id::EH_FRAME_HDR,
                size_of::<EhFrameHdrEntry>() as u64 * num_frames,
            );
        }

        Ok(())
    }

    fn load_debug_section<A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,

        part_id: PartId,
        section_index: SectionIndex,
        resources: &GraphResources<'data, '_>,
    ) -> Result {
        let header = self.object.section(section_index)?;
        let section = Section::create(header, self, section_index, part_id)?;
        if A::local_symbols_in_debug_info() {
            match self.relocations(section.index)? {
                RelocationList::Rela(relocations) => self.load_debug_relocations::<A>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.crel_iter(),
                )?,
                RelocationList::Crel(relocations) => self.load_debug_relocations::<A>(
                    common,
                    queue,
                    resources,
                    section,
                    relocations.flat_map(|r| r.ok()),
                )?,
            }
        }

        tracing::debug!(loaded_debug_section = %self.object.section_display_name(section_index),);
        common.section_loaded(part_id, header, section);
        self.sections[section_index.0] = SectionSlot::LoadedDebugInfo(section);

        Ok(())
    }

    fn load_debug_relocations<A: Arch>(
        &self,
        common: &mut CommonGroupState<'data>,
        queue: &mut LocalWorkQueue,
        resources: &GraphResources<'data, '_>,
        section: Section,
        relocations: impl Iterator<Item = Crel>,
    ) -> Result<(), Error> {
        for rel in relocations {
            let modifier = process_relocation::<A>(
                self,
                common,
                &rel,
                self.object.section(section.index)?,
                resources,
                queue,
                true,
            )
            .with_context(|| {
                format!(
                    "Failed to copy section {} from file {self}",
                    section_debug(self.object, section.index)
                )
            })?;
            ensure!(
                modifier == RelocationModifier::Normal,
                "All debug relocations must be processed"
            );
        }

        Ok(())
    }

    fn finalise_sizes(
        &mut self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data>,
        output_sections: &OutputSections,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) {
        common.mem_sizes.resize(output_sections.num_parts());
        if !symbol_db.args.strip_all {
            self.allocate_symtab_space(common, symbol_db, symbol_resolution_flags);
        }
        let output_kind = symbol_db.args.output_kind();
        for slot in &mut self.sections {
            if let SectionSlot::Loaded(section) = slot {
                allocate_resolution(
                    ValueFlags::ADDRESS,
                    section.resolution_flags,
                    &mut common.mem_sizes,
                    output_kind,
                );
            }
        }
        // TODO: Deduplicate CIEs from different objects, then only allocate space for those CIEs
        // that we "won".
        for cie in &self.cies {
            self.eh_frame_size += cie.cie.bytes.len() as u64;
        }
        common.allocate(part_id::EH_FRAME, self.eh_frame_size);
    }

    fn allocate_symtab_space(
        &self,
        common: &mut CommonGroupState,
        symbol_db: &SymbolDb<'data>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) {
        let _file_span = symbol_db.args.trace_span_for_file(self.file_id());

        let mut num_locals = 0;
        let mut num_globals = 0;
        let mut strings_size = 0;
        for ((sym_index, sym), sym_state) in self
            .object
            .symbols
            .enumerate()
            .zip(&symbol_resolution_flags[self.symbol_id_range().as_usize()])
        {
            let symbol_id = self.symbol_id_range.input_to_id(sym_index);
            if let Some(info) = SymbolCopyInfo::new(
                self.object,
                sym_index,
                sym,
                symbol_id,
                symbol_db,
                sym_state.get(),
                &self.sections,
            ) {
                // If we've decided to emit the symbol even though it's not referenced (because it's
                // in a section we're emitting), then make sure we have a resolution for it.
                sym_state.fetch_or(ResolutionFlags::DIRECT);
                if sym.is_local() {
                    num_locals += 1;
                } else {
                    num_globals += 1;
                }
                let name = RawSymbolName::parse(info.name).name;
                strings_size += name.len() + 1;
            }
        }
        let entry_size = size_of::<elf::SymtabEntry>() as u64;
        common.allocate(part_id::SYMTAB_LOCAL, num_locals * entry_size);
        common.allocate(part_id::SYMTAB_GLOBAL, num_globals * entry_size);
        common.allocate(part_id::STRTAB, strings_size as u64);
    }

    fn finalise_layout(
        mut self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<ObjectLayout<'data>> {
        let _file_span = resources.symbol_db.args.trace_span_for_file(self.file_id());
        let symbol_id_range = self.symbol_id_range();

        let emitter = create_global_address_emitter(resources.symbol_resolution_flags);

        let mut section_resolutions = Vec::with_capacity(self.sections.len());
        for slot in &mut self.sections {
            let resolution = match slot {
                SectionSlot::Loaded(sec) => {
                    let part_id = sec.part_id;
                    let address = *memory_offsets.get(part_id);
                    // TODO: We probably need to be able to handle sections that are ifuncs and sections
                    // that need a TLS GOT struct.
                    *memory_offsets.get_mut(part_id) += sec.capacity();
                    SectionResolution { address }
                }
                &mut SectionSlot::LoadedDebugInfo(sec) => {
                    let address = *memory_offsets.get(sec.part_id);
                    *memory_offsets.get_mut(sec.part_id) += sec.capacity();
                    SectionResolution { address }
                }
                SectionSlot::EhFrameData(..) => {
                    // References to symbols defined in .eh_frame are a bit weird, since it's a
                    // section where we're GCing stuff, but crtbegin.o and crtend.o use them in
                    // order to find the start and end of the whole .eh_frame section.
                    let address = *memory_offsets.get(part_id::EH_FRAME);
                    SectionResolution { address }
                }
                _ => SectionResolution::none(),
            };
            section_resolutions.push(resolution);
        }

        for ((local_symbol_index, local_symbol), &resolution_flags) in self
            .object
            .symbols
            .enumerate()
            .zip(&resources.symbol_resolution_flags[symbol_id_range.as_usize()])
        {
            self.finalise_symbol(
                resources,
                resolution_flags,
                local_symbol,
                local_symbol_index,
                &section_resolutions,
                memory_offsets,
                &emitter,
                resolutions_out,
            )?;
        }

        memory_offsets.increment(part_id::EH_FRAME, self.eh_frame_size);

        Ok(ObjectLayout {
            input: self.input,
            file_id: self.file_id,
            object: self.object,
            sections: self.sections,
            relocations: self.relocations,
            section_resolutions,
            symbol_id_range,
        })
    }

    fn finalise_symbol<'scope>(
        &self,
        resources: &FinaliseLayoutResources<'scope, 'data>,
        resolution_flags: ResolutionFlags,
        local_symbol: &object::elf::Sym64<LittleEndian>,
        local_symbol_index: object::SymbolIndex,
        section_resolutions: &[SectionResolution],
        memory_offsets: &mut OutputSectionPartMap<u64>,
        emitter: &GlobalAddressEmitter<'scope>,
        resolutions_out: &mut ResolutionWriter,
    ) -> Result {
        let resolution = self.create_symbol_resolution(
            resources,
            resolution_flags,
            local_symbol,
            local_symbol_index,
            section_resolutions,
            memory_offsets,
            emitter,
        )?;

        resolutions_out.write(resolution)
    }

    fn create_symbol_resolution<'scope>(
        &self,
        resources: &FinaliseLayoutResources<'scope, 'data>,
        resolution_flags: ResolutionFlags,
        local_symbol: &object::elf::Sym64<LittleEndian>,
        local_symbol_index: object::SymbolIndex,
        section_resolutions: &[SectionResolution],
        memory_offsets: &mut OutputSectionPartMap<u64>,
        emitter: &GlobalAddressEmitter<'scope>,
    ) -> Result<Option<Resolution>> {
        let symbol_id_range = self.symbol_id_range();
        let symbol_id = symbol_id_range.input_to_id(local_symbol_index);

        if resolution_flags.is_empty() || !resources.symbol_db.is_canonical(symbol_id) {
            return Ok(None);
        }

        let e = LittleEndian;
        let value_flags = resources.symbol_db.local_symbol_value_flags(symbol_id);

        let raw_value = if let Some(section_index) = self
            .object
            .symbol_section(local_symbol, local_symbol_index)?
        {
            if let Some(section_address) = section_resolutions[section_index.0].address() {
                local_symbol.st_value(e) + section_address
            } else {
                match get_merged_string_output_address(
                    local_symbol_index,
                    0,
                    self.object,
                    &self.sections,
                    resources.merged_strings,
                    resources.merged_string_start_addresses,
                    true,
                )? {
                    Some(x) => x,
                    None => {
                        // Don't error for mapping symbols. They cannot have relocations refer to
                        // them, so we don't need to produce a resolution.
                        if resources.symbol_db.is_mapping_symbol(symbol_id) {
                            return Ok(None);
                        }
                        bail!(
                            "Symbol is in a section that we didn't load. \
                             Symbol: {} Section: {} Res: {resolution_flags}",
                            resources.symbol_db.symbol_debug(symbol_id),
                            section_debug(self.object, section_index),
                        );
                    }
                }
            }
        } else if local_symbol.is_common(e) {
            let common = CommonSymbol::new(local_symbol)?;
            let offset = memory_offsets
                .get_mut(output_section_id::BSS.part_id_with_alignment(common.alignment));
            let address = *offset;
            *offset += common.size;
            address
        } else {
            local_symbol.st_value(e)
        };

        let mut dynamic_symbol_index = None;
        if value_flags.is_dynamic() {
            // This is an undefined weak symbol. Emit it as a dynamic symbol so that it can be
            // overridden at runtime.
            let dyn_sym_index = take_dynsym_index(memory_offsets, resources.section_layouts)?;
            dynamic_symbol_index = Some(
                NonZeroU32::new(dyn_sym_index)
                    .context("Attempted to create dynamic symbol index 0")?,
            );
        }

        Ok(Some(create_resolution(
            emitter.symbol_resolution_flags[symbol_id.as_usize()],
            raw_value,
            dynamic_symbol_index,
            value_flags,
            memory_offsets,
        )))
    }

    fn load_non_hidden_symbols<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
        export_all_dynamic: bool,
    ) -> Result {
        for (sym_index, sym) in self.object.symbols.enumerate() {
            let symbol_id = self.symbol_id_range().input_to_id(sym_index);

            if !can_export_symbol(sym, symbol_id, resources.symbol_db, export_all_dynamic) {
                continue;
            }

            let old_flags = resources.symbol_resolution_flags[symbol_id.as_usize()]
                .fetch_or(ResolutionFlags::EXPORT_DYNAMIC);

            if old_flags.is_empty() {
                self.load_symbol::<A>(common, symbol_id, resources, queue)?;
            }

            if !old_flags.needs_export_dynamic() {
                export_dynamic(common, symbol_id, resources.symbol_db)?;
            }
        }
        Ok(())
    }

    fn export_dynamic<'scope, A: Arch>(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let sym = self
            .object
            .symbol(self.symbol_id_range.id_to_input(symbol_id))?;

        // Shared objects that we're linking against sometimes define symbols that are also defined
        // in regular object. When that happens, if we resolve the symbol to the definition from the
        // regular object, then the shared object might send us a request to export the definition
        // provided by the regular object. This isn't always possible, since the symbol might be
        // hidden.
        if !can_export_symbol(sym, symbol_id, resources.symbol_db, true) {
            return Ok(());
        }

        let old_flags = resources.symbol_resolution_flags[symbol_id.as_usize()]
            .fetch_or(ResolutionFlags::EXPORT_DYNAMIC);

        if old_flags.is_empty() {
            self.load_symbol::<A>(common, symbol_id, resources, queue)?;
        }

        if !old_flags.needs_export_dynamic() {
            export_dynamic(common, symbol_id, resources.symbol_db)?;
        }

        Ok(())
    }

    fn relocations(&self, index: SectionIndex) -> Result<RelocationList<'data>> {
        self.object.relocations(index, &self.relocations)
    }
}

pub(crate) struct SymbolCopyInfo<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> SymbolCopyInfo<'data> {
    /// The primary purpose of this function is to determine whether a symbol should be copied into
    /// the symtab. In the process, we also return the name of the symbol, to avoid needing to read
    /// it again.
    #[inline(always)]
    pub(crate) fn new(
        object: &crate::elf::File<'data>,
        sym_index: object::SymbolIndex,
        sym: &crate::elf::Symbol,
        symbol_id: SymbolId,
        symbol_db: &SymbolDb<'data>,
        symbol_state: ResolutionFlags,
        sections: &[SectionSlot],
    ) -> Option<SymbolCopyInfo<'data>> {
        let e = LittleEndian;
        if !symbol_db.is_canonical(symbol_id) || sym.is_undefined(e) {
            return None;
        }

        if let Ok(Some(section)) = object.symbol_section(sym, sym_index)
            && !sections[section.0].is_loaded()
        {
            // Symbol is in a discarded section.
            return None;
        }

        if sym.is_common(e) && symbol_state.is_empty() {
            return None;
        }

        // Reading the symbol name is slightly expensive, so we want to do that after all the other
        // checks. That's also the reason why we return the symbol name, so that the caller, if it
        // needs the name, doesn't have a go and read it again.
        let name = object.symbol_name(sym).ok()?;
        if name.is_empty()
            || (sym.is_local() && name.starts_with(b".L"))
            || is_mapping_symbol_name(name)
        {
            return None;
        }

        Some(SymbolCopyInfo { name })
    }
}

/// Returns whether the supplied symbol can be exported when we're outputting a shared object.
fn can_export_symbol(
    sym: &crate::elf::SymtabEntry,
    symbol_id: SymbolId,
    symbol_db: &SymbolDb,
    export_all_dynamic: bool,
) -> bool {
    if sym.is_undefined(LittleEndian) || sym.is_local() {
        return false;
    }

    let visibility = sym.st_visibility();

    if visibility != object::elf::STV_DEFAULT && visibility != object::elf::STV_PROTECTED {
        return false;
    }

    if !symbol_db.is_canonical(symbol_id) {
        return false;
    }

    let value_flags = symbol_db.local_symbol_value_flags(symbol_id);

    if value_flags.is_downgraded_to_local() {
        return false;
    }

    if !export_all_dynamic
        && let Some(export_list) = &symbol_db.export_list
        && let Ok(symbol_name) = symbol_db.symbol_name(symbol_id)
        && !&export_list.contains(&UnversionedSymbolName::prehashed(symbol_name.bytes()))
    {
        return false;
    }

    true
}

fn process_eh_frame_data<'data, A: Arch>(
    object: &mut ObjectLayoutState<'data>,
    common: &mut CommonGroupState<'data>,
    file_symbol_id_range: SymbolIdRange,
    eh_frame_section_index: object::SectionIndex,
    resources: &GraphResources,
    queue: &mut LocalWorkQueue,
) -> Result {
    let eh_frame_section = object.object.section(eh_frame_section_index)?;
    let data = object.object.raw_section_data(eh_frame_section)?;
    match object.relocations(eh_frame_section_index)? {
        RelocationList::Rela(relocations) => process_eh_frame_relocations::<A>(
            object,
            common,
            file_symbol_id_range,
            resources,
            queue,
            eh_frame_section,
            data,
            &relocations,
        ),
        RelocationList::Crel(crel_iterator) => process_eh_frame_relocations::<A>(
            object,
            common,
            file_symbol_id_range,
            resources,
            queue,
            eh_frame_section,
            data,
            &crel_iterator.collect::<Result<Vec<Crel>, _>>()?,
        ),
    }
}

fn process_eh_frame_relocations<'data, 'rel: 'data, A: Arch>(
    object: &mut ObjectLayoutState<'data>,
    common: &mut CommonGroupState<'data>,
    file_symbol_id_range: SymbolIdRange,
    resources: &GraphResources<'_, '_>,
    queue: &mut LocalWorkQueue,
    eh_frame_section: &'data object::elf::SectionHeader64<LittleEndian>,
    data: &'data [u8],
    relocations: &impl RelocationSequence<'rel>,
) -> Result {
    const PREFIX_LEN: usize = size_of::<elf::EhFrameEntryPrefix>();

    let mut rel_iter = relocations.crel_iter().enumerate().peekable();
    let mut offset = 0;

    while offset + PREFIX_LEN <= data.len() {
        // Although the section data will be aligned within the object file, there's
        // no guarantee that the object is aligned within the archive to any more
        // than 2 bytes, so we can't rely on alignment here. Archives are annoying!
        // See https://www.airs.com/blog/archives/170
        let prefix: elf::EhFrameEntryPrefix =
            bytemuck::pod_read_unaligned(&data[offset..offset + PREFIX_LEN]);
        let size = size_of_val(&prefix.length) + prefix.length as usize;
        let next_offset = offset + size;

        if next_offset > data.len() {
            bail!("Invalid .eh_frame data");
        }

        if prefix.cie_id == 0 {
            // This is a CIE
            let mut referenced_symbols: SmallVec<[SymbolId; 1]> = Default::default();
            // When deduplicating CIEs, we take into consideration the bytes of the CIE and all the
            // symbols it references. If however, it references something other than a symbol, then,
            // because we're not taking that into consideration, we disallow deduplication.
            let mut eligible_for_deduplication = true;
            while let Some((_, rel)) = rel_iter.peek() {
                let rel_offset = rel.r_offset;
                if rel_offset >= next_offset as u64 {
                    // This relocation belongs to the next entry.
                    break;
                }

                // We currently always load all CIEs, so any relocations found in CIEs always need
                // to be processed.
                process_relocation::<A>(
                    object,
                    common,
                    rel,
                    eh_frame_section,
                    resources,
                    queue,
                    false,
                )?;

                if let Some(local_sym_index) = rel.symbol() {
                    let local_symbol_id = file_symbol_id_range.input_to_id(local_sym_index);
                    let definition = resources.symbol_db.definition(local_symbol_id);
                    referenced_symbols.push(definition);
                } else {
                    eligible_for_deduplication = false;
                }
                rel_iter.next();
            }

            object.cies.push(CieAtOffset {
                offset: offset as u32,
                cie: Cie {
                    bytes: &data[offset..next_offset],
                    eligible_for_deduplication,
                    referenced_symbols,
                },
            });
        } else {
            // This is an FDE
            let mut section_index = None;
            let rel_start_index = rel_iter.peek().map_or(0, |(i, _)| *i);
            let mut rel_end_index = 0;

            while let Some((rel_index, rel)) = rel_iter.peek() {
                let rel_offset = rel.r_offset;
                if rel_offset < next_offset as u64 {
                    let is_pc_begin = (rel_offset as usize - offset) == elf::FDE_PC_BEGIN_OFFSET;

                    if is_pc_begin && let Some(index) = rel.symbol() {
                        let elf_symbol = object.object.symbol(index)?;
                        section_index = object.object.symbol_section(elf_symbol, index)?;
                    }
                    rel_end_index = rel_index + 1;
                    rel_iter.next();
                } else {
                    break;
                }
            }

            if let Some(section_index) = section_index
                && let Some(unloaded) = object.sections[section_index.0].unloaded_mut()
            {
                let frame_index = FrameIndex::from_usize(object.exception_frames.len());

                // Update our unloaded section to point to our new frame. Our frame will then in
                // turn point to whatever the section pointed to before.
                let previous_frame_for_section = unloaded.last_frame_index.replace(frame_index);

                object.exception_frames.push(ExceptionFrame {
                    relocations: relocations.subsequence(rel_start_index..rel_end_index),
                    frame_size: size as u32,
                    previous_frame_for_section,
                });
            }
        }
        offset = next_offset;
    }

    // Allocate space for any remaining bytes in .eh_frame that aren't large enough to constitute an
    // actual entry. crtend.o has a single u32 equal to 0 as an end marker.
    object.eh_frame_size += (data.len() - offset) as u64;
    Ok(())
}

fn process_gnu_property_note(
    object: &mut ObjectLayoutState,
    note_section_index: object::SectionIndex,
) -> Result {
    let section = object.object.section(note_section_index)?;
    let e = LittleEndian;

    let Some(notes) = section.notes(e, object.object.data)? else {
        return Ok(());
    };

    for note in notes {
        for gnu_property in note?
            .gnu_properties(e)
            .ok_or(error!("Invalid type of .note.gnu.property"))?
        {
            let gnu_property = gnu_property?;

            // Right now, skip all properties other than those with size equal to 4.
            // There are existing properties, but unused right now:
            // GNU_PROPERTY_STACK_SIZE, GNU_PROPERTY_NO_COPY_ON_PROTECTED
            // TODO: support in the future
            if gnu_property.pr_data().len() != 4 {
                continue;
            }
            object.gnu_property_notes.push(GnuProperty {
                ptype: gnu_property.pr_type(),
                data: gnu_property.data_u32(e)?,
            });
        }
    }

    Ok(())
}

fn process_riscv_attributes(
    object: &mut ObjectLayoutState,
    riscv_attributes_section_index: object::SectionIndex,
) -> Result {
    let section = object.object.section(riscv_attributes_section_index)?;
    let e = LittleEndian;

    let content = section.data(e, object.object.data)?;
    ensure!(content.starts_with(b"A"), "Header must start with 'A'");
    let mut content = &content[1..];

    let read_uleb128 = |content: &mut &[u8]| leb128::read::unsigned(content);
    let read_string = |content: &mut &[u8]| -> Result<String> {
        let string = CStr::from_bytes_until_nul(content)?;
        *content = &content[string.count_bytes() + 1..];
        Ok(string.to_string_lossy().to_string())
    };
    let read_u32 = |content: &mut &[u8]| -> Result<u32> {
        let value = u32::from_le_bytes(content[..4].try_into()?);
        *content = &content[4..];
        Ok(value)
    };

    // Expect only one subsection
    let _size = read_u32(&mut content)?;
    let vendor = read_string(&mut content).context("Cannot read vendor string")?;
    ensure!(
        vendor == RISCV_ATTRIBUTE_VENDOR_NAME,
        "Unsupported vendor ('{vendor:?}') subsection"
    );

    // Assume only one sub-sub-section
    let tag = read_uleb128(&mut content).context("Cannot read tag of subsection")?;
    ensure!(tag == TAG_RISCV_WHOLE_FILE, "Whole file tag expected");
    let _size = read_u32(&mut content)?;
    let mut attributes = Vec::new();

    while !content.is_empty() {
        let tag = read_uleb128(&mut content).context("Cannot read tag of sub-subsection")?;
        let attribute = match tag {
            TAG_RISCV_STACK_ALIGN => {
                let align = read_uleb128(&mut content).context("Cannot read stack alignment")?;
                RiscVAttribute::StackAlign(align)
            }
            TAG_RISCV_ARCH => {
                let arch = read_string(&mut content).context("Cannot read arch attributes")?;
                let components = arch
                    .split('_')
                    .map(|part| {
                        let mut it = part.chars().rev();
                        let minor = it
                            .next()
                            .ok_or_else(|| crate::error!("Cannot parse minor"))?
                            .to_string();
                        let p = it
                            .next()
                            .ok_or_else(|| crate::error!("Cannot parse 'p' separator"))?;
                        ensure!(p == 'p', "Separator expected");
                        let major = it
                            .next()
                            .ok_or_else(|| crate::error!("Cannot parse major"))?
                            .to_string();
                        let name = String::from_iter(it.rev());
                        Ok((name, (major.parse()?, minor.parse()?)))
                    })
                    .collect::<Result<IndexMap<_, _>>>()?;

                RiscVAttribute::Arch(RiscVArch { map: components })
            }
            TAG_RISCV_UNALIGNED_ACCESS => {
                let access = read_uleb128(&mut content).context("Cannot read unaligned access")?;
                RiscVAttribute::UnalignedAccess(access > 0)
            }
            TAG_RISCV_PRIV_SPEC => {
                let version =
                    read_uleb128(&mut content).context("Cannot read privileged major version")?;
                RiscVAttribute::PrivilegedSpecMajor(version)
            }
            TAG_RISCV_PRIV_SPEC_MINOR => {
                let version =
                    read_uleb128(&mut content).context("Cannot read privileged minor version")?;
                RiscVAttribute::PrivilegedSpecMinor(version)
            }
            TAG_RISCV_PRIV_SPEC_REVISION => {
                let version = read_uleb128(&mut content)
                    .context("Cannot read privileged revision version")?;
                RiscVAttribute::PrivilegedSpecRevision(version)
            }
            TAG_RISCV_ATOMIC_ABI => {
                let _abi = read_uleb128(&mut content).context("Cannot read atomic ABI")?;
                bail!("TAG_RISCV_ATOMIC_ABI is not supported yet");
            }
            TAG_RISCV_X3_REG_USAGE => {
                let _x3 = read_uleb128(&mut content).context("Cannot read x3 register usage")?;
                bail!("TAG_RISCV_X3_REG_USAGE is not supported yet");
            }
            _ => {
                bail!("Unsupported tag: {tag}");
            }
        };
        attributes.push(attribute);
    }

    object.riscv_attributes = attributes;
    ensure!(content.is_empty(), "Unexpected multiple sub-sections");

    Ok(())
}

/// A "common information entry". This is part of the .eh_frame data in ELF.
#[derive(PartialEq, Eq, Hash)]
struct Cie<'data> {
    bytes: &'data [u8],
    eligible_for_deduplication: bool,
    referenced_symbols: SmallVec<[SymbolId; 1]>,
}

struct CieAtOffset<'data> {
    // TODO: Use or remove. I think we need this when we implement deduplication of CIEs.
    /// Offset within .eh_frame
    #[allow(dead_code)]
    offset: u32,
    cie: Cie<'data>,
}

#[derive(Clone, Copy)]
struct CommonSymbol {
    size: u64,
    alignment: Alignment,
}

impl CommonSymbol {
    fn new(local_symbol: &crate::elf::SymtabEntry) -> Result<CommonSymbol> {
        let e = LittleEndian;
        debug_assert!(local_symbol.is_common(e));
        // Common symbols misuse the value field (which we access via `address()`) to store the
        // alignment.
        let alignment = Alignment::new(local_symbol.st_value(e))?;
        let size = alignment.align_up(local_symbol.st_size(e));
        Ok(CommonSymbol { size, alignment })
    }
}

struct GlobalAddressEmitter<'state> {
    symbol_resolution_flags: &'state [ResolutionFlags],
}

struct ResolutionWriter<'writer, 'out> {
    resolutions_out: &'writer mut sharded_vec_writer::Shard<'out, Option<Resolution>>,
}

impl ResolutionWriter<'_, '_> {
    fn write(&mut self, res: Option<Resolution>) -> Result {
        self.resolutions_out.try_push(res)?;
        Ok(())
    }
}

#[inline(always)]
fn create_resolution(
    res_kind: ResolutionFlags,
    raw_value: u64,
    dynamic_symbol_index: Option<NonZeroU32>,
    value_flags: ValueFlags,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> Resolution {
    let mut resolution = Resolution {
        raw_value,
        dynamic_symbol_index,
        got_address: None,
        plt_address: None,
        resolution_flags: res_kind,
        value_flags,
    };
    if res_kind.needs_plt() {
        let plt_address = allocate_plt(memory_offsets);
        resolution.plt_address = Some(plt_address);
        if value_flags.is_dynamic() {
            resolution.raw_value = plt_address.get();
        }
        resolution.got_address = Some(allocate_got(1, memory_offsets));
    } else if res_kind.needs_got() {
        resolution.got_address = Some(allocate_got(1, memory_offsets));
    } else {
        // Handle the TLS GOT addresses where we can combine up to 3 different access methods.
        let mut num_got_slots = 0;
        if res_kind.needs_got_tls_offset() {
            num_got_slots += 1;
        }
        if res_kind.needs_got_tls_module() {
            num_got_slots += 2;
        }
        if res_kind.needs_got_tls_descriptor() {
            num_got_slots += 2;
        }
        if num_got_slots > 0 {
            resolution.got_address = Some(allocate_got(num_got_slots, memory_offsets));
        }
    }
    resolution
}

fn allocate_got(num_entries: u64, memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let got_address = NonZeroU64::new(*memory_offsets.get(part_id::GOT)).unwrap();
    memory_offsets.increment(part_id::GOT, elf::GOT_ENTRY_SIZE * num_entries);
    got_address
}

fn allocate_plt(memory_offsets: &mut OutputSectionPartMap<u64>) -> NonZeroU64 {
    let plt_address = NonZeroU64::new(*memory_offsets.get(part_id::PLT_GOT)).unwrap();
    memory_offsets.increment(part_id::PLT_GOT, elf::PLT_ENTRY_SIZE);
    plt_address
}

impl<'data> resolution::ResolvedFile<'data> {
    fn create_layout_state(self) -> FileLayoutState<'data> {
        match self {
            resolution::ResolvedFile::Object(s) => new_object_layout_state(s),
            resolution::ResolvedFile::Prelude(s) => {
                FileLayoutState::Prelude(PreludeLayoutState::new(s))
            }
            resolution::ResolvedFile::NotLoaded(s) => FileLayoutState::NotLoaded(s),
            resolution::ResolvedFile::LinkerScript(s) => {
                FileLayoutState::LinkerScript(LinkerScriptLayoutState::new(s))
            }
            resolution::ResolvedFile::Epilogue(s) => {
                FileLayoutState::Epilogue(EpilogueLayoutState::new(s))
            }
        }
    }
}

impl Resolution {
    pub(crate) fn got_address(&self) -> Result<u64> {
        Ok(self.got_address.context("Missing GOT address")?.get())
    }

    pub(crate) fn tlsgd_got_address(&self) -> Result<u64> {
        debug_assert_bail!(
            self.resolution_flags.needs_got_tls_module(),
            "Called tlsgd_got_address without GOT_TLS_MODULE being set"
        );
        // If we've got both a GOT_TLS_OFFSET and a GOT_TLS_MODULE, then the latter comes second.
        let mut got_address = self.got_address()?;
        if self.resolution_flags.needs_got_tls_offset() {
            got_address += elf::GOT_ENTRY_SIZE;
        }
        Ok(got_address)
    }

    pub(crate) fn tls_descriptor_got_address(&self) -> Result<u64> {
        debug_assert_bail!(
            self.resolution_flags.needs_got_tls_descriptor(),
            "Called tls_descriptor_got_address without GOT_TLS_DESCRIPTOR being set"
        );
        // We might have both GOT_TLS_OFFSET, GOT_TLS_MODULE and GOT_TLS_DESCRIPTOR at the same time
        // for a single symbol. Then the TLS descriptor comes as the last one.
        let mut got_address = self.got_address()?;
        if self.resolution_flags.needs_got_tls_offset() {
            got_address += elf::GOT_ENTRY_SIZE;
        }
        if self.resolution_flags.needs_got_tls_module() {
            got_address += 2 * elf::GOT_ENTRY_SIZE;
        }

        Ok(got_address)
    }

    pub(crate) fn plt_address(&self) -> Result<u64> {
        Ok(self.plt_address.context("Missing PLT address")?.get())
    }

    pub(crate) fn value_flags(self) -> ValueFlags {
        self.value_flags
    }

    pub(crate) fn value(self) -> u64 {
        self.raw_value
    }

    pub(crate) fn address(&self) -> Result<u64> {
        if !self.value_flags.is_address() {
            bail!("Expected address, found {}", self.value_flags);
        }
        Ok(self.raw_value)
    }

    pub(crate) fn value_for_symbol_table(&self) -> u64 {
        self.raw_value
    }

    pub(crate) fn is_absolute(&self) -> bool {
        self.value_flags.is_absolute()
    }

    pub(crate) fn dynamic_symbol_index(&self) -> Result<u32> {
        Ok(self
            .dynamic_symbol_index
            .context("Missing dynamic_symbol_index")?
            .get())
    }

    #[inline(always)]
    pub(crate) fn value_with_addend(
        &self,
        addend: i64,
        symbol_index: object::SymbolIndex,
        object_layout: &ObjectLayout,
        merged_strings: &OutputSectionMap<MergedStringsSection>,
        merged_string_start_addresses: &MergedStringStartAddresses,
    ) -> Result<u64> {
        if self.value_flags.is_ifunc() {
            return Ok(self.plt_address()?.wrapping_add(addend as u64));
        }

        // For most symbols, `raw_value` won't be zero, so we can save ourselves from looking up the
        // section to see if it's a string-merge section. For string-merge symbols with names,
        // `raw_value` will have already been computed, so we can avoid computing it again.
        if self.raw_value == 0
            && let Some(r) = get_merged_string_output_address(
                symbol_index,
                addend,
                object_layout.object,
                &object_layout.sections,
                merged_strings,
                merged_string_start_addresses,
                false,
            )?
        {
            if self.raw_value != 0 {
                bail!("Merged string resolution has value 0x{}", self.raw_value);
            }
            return Ok(r);
        }
        Ok(self.raw_value.wrapping_add(addend as u64))
    }
}

fn layout_section_parts(
    sizes: &OutputSectionPartMap<u64>,
    output_sections: &OutputSections,
    program_segments: &ProgramSegments,
    output_order: &OutputOrder,
    args: &Args,
) -> OutputSectionPartMap<OutputRecordLayout> {
    let mut file_offset = 0;
    let mut mem_offset = output_sections.base_address;
    let mut nonalloc_mem_offsets: OutputSectionMap<u64> =
        OutputSectionMap::with_size(output_sections.num_sections());

    let mut pending_location = None;

    let mut records_out = output_sections.new_part_map();

    for event in output_order {
        match event {
            OrderEvent::SetLocation(location) => {
                pending_location = Some(location);
            }
            OrderEvent::SegmentStart(segment_id) => {
                if program_segments.is_load_segment(segment_id) {
                    let segment_alignment = program_segments.segment_alignment(segment_id, args);
                    if let Some(location) = pending_location.take() {
                        mem_offset = location.address;
                        file_offset =
                            segment_alignment.align_modulo(mem_offset, file_offset as u64) as usize;
                    } else {
                        mem_offset = segment_alignment.align_modulo(file_offset as u64, mem_offset);
                    }
                }
            }
            OrderEvent::SegmentEnd(_) => {}
            OrderEvent::Section(section_id) => {
                debug_assert!(
                    pending_location.is_none(),
                    "SetLocation, Section without SegmentStart"
                );
                let section_info = output_sections.output_info(section_id);
                let part_id_range = section_id.part_id_range();
                let max_alignment = sizes.max_alignment(part_id_range.clone());
                if let Some(location) = section_info.location {
                    mem_offset = location.address;
                }

                records_out[part_id_range.clone()]
                    .iter_mut()
                    .zip(&sizes[part_id_range.clone()])
                    .enumerate()
                    .for_each(|(offset, (part_layout, &part_size))| {
                        let part_id = part_id_range.start.offset(offset);
                        let alignment = part_id.alignment().min(max_alignment);
                        let merge_target = output_sections.primary_output_section(section_id);
                        let section_flags = output_sections.section_flags(merge_target);
                        let mem_size = part_size;

                        // Note, we align up even if our size is zero, otherwise our section will start at an
                        // unaligned address.
                        file_offset = alignment.align_up_usize(file_offset);

                        if section_flags.contains(shf::ALLOC) {
                            mem_offset = alignment.align_up(mem_offset);

                            let file_size = if output_sections.has_data_in_file(merge_target) {
                                mem_size as usize
                            } else {
                                0
                            };

                            *part_layout = OutputRecordLayout {
                                file_size,
                                mem_size,
                                alignment,
                                file_offset,
                                mem_offset,
                            };

                            file_offset += file_size;
                            mem_offset += mem_size;
                        } else {
                            let section_id = part_id.output_section_id();
                            let mem_offset =
                                alignment.align_up(*nonalloc_mem_offsets.get(section_id));

                            *nonalloc_mem_offsets.get_mut(section_id) += mem_size;

                            *part_layout = OutputRecordLayout {
                                file_size: mem_size as usize,
                                mem_size,
                                alignment,
                                file_offset,
                                mem_offset,
                            };
                            file_offset += mem_size as usize;
                        }
                    });
            }
        };
    }

    records_out
}

impl<'data> DynamicLayoutState<'data> {
    fn activate(
        &mut self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, '_>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        self.symbol_versions_needed = vec![false; self.object.verdefnum as usize];

        let dt_info = DynamicTagValues::read(self.object)?;
        if let Some(soname) = dt_info.soname {
            self.lib_name = soname;
        }

        common.allocate(
            part_id::DYNAMIC,
            size_of::<crate::elf::DynamicEntry>() as u64,
        );

        common.allocate(part_id::DYNSTR, self.lib_name.len() as u64 + 1);

        self.request_all_undefined_symbols(resources, queue)
    }

    fn request_all_undefined_symbols(
        &self,
        resources: &GraphResources<'data, '_>,
        queue: &mut LocalWorkQueue,
    ) -> Result {
        let mut check_undefined_cache = None;

        for symbol_id in self.symbol_id_range() {
            let definition_symbol_id = resources.symbol_db.definition(symbol_id);

            let value_flags = resources
                .symbol_db
                .local_symbol_value_flags(definition_symbol_id);

            if value_flags.is_dynamic() && value_flags.is_absolute() {
                // Our shared object references an undefined symbol. Whether that is an error or
                // not, depends on flags, whether the symbol is weak and whether all of the shared
                // object's dependencies are loaded.

                let args = resources.symbol_db.args;
                let check_undefined = *check_undefined_cache.get_or_insert_with(|| {
                    !args.allow_shlib_undefined
                        && args.output_kind().is_executable()
                        // Like lld, our behaviour for --no-allow-shlib-undefined is to only report
                        // errors for shared objects that have all their dependencies in the link.
                        // This is in contrast to GNU ld which recursively loads all transitive
                        // dependencies of shared objects and checks our shared object against
                        // those.
                        && self.has_complete_deps(resources)
                });

                if check_undefined {
                    let symbol = self
                        .object
                        .symbol(self.symbol_id_range.id_to_input(symbol_id))?;
                    if !symbol.is_weak() {
                        let should_report = !matches!(
                            args.unresolved_symbols,
                            crate::args::UnresolvedSymbols::IgnoreAll
                                | crate::args::UnresolvedSymbols::IgnoreInSharedLibs
                        );

                        if should_report {
                            let symbol_name =
                                resources.symbol_db.symbol_name_for_display(symbol_id);

                            if args.error_unresolved_symbols {
                                bail!("undefined reference to `{symbol_name}` from {self}");
                            }
                            crate::error::warning(&format!(
                                "undefined reference to `{symbol_name}` from {self}"
                            ));
                        }
                    }
                }
            } else if definition_symbol_id != symbol_id {
                let file_id = resources.symbol_db.file_id_for_symbol(definition_symbol_id);

                queue.send_work(
                    resources,
                    file_id,
                    WorkItem::ExportDynamic(definition_symbol_id),
                );
            }
        }

        Ok(())
    }

    fn finalise_copy_relocations(
        &mut self,
        common: &mut CommonGroupState<'data>,
        symbol_db: &SymbolDb<'data>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        // Skip iterating over our symbol table if we don't have any copy relocations.
        if self.copy_relocations.is_empty() {
            return Ok(());
        }

        self.select_copy_relocation_alternatives(symbol_resolution_flags, common, symbol_db)
    }

    fn finalise_sizes(&mut self, common: &mut CommonGroupState<'data>) -> Result {
        self.allocate_for_copy_relocations(common)?;
        self.allocate_for_versions(common)
    }

    fn allocate_for_versions(&mut self, common: &mut CommonGroupState<'data>) -> Result {
        let e = LittleEndian;
        let mut version_count = 0;

        if let Some((mut verdef_iterator, link)) = self.object.verdef.clone() {
            let defs = verdef_iterator.clone();

            let strings = self.object.sections.strings(e, self.object.data, link)?;
            let mut base_size = 0;
            while let Some((verdef, mut aux_iterator)) = verdef_iterator.next()? {
                let version_index = verdef.vd_ndx.get(e);

                if version_index == 0 {
                    bail!("Invalid version index");
                }

                let flags = verdef.vd_flags.get(e);
                let is_base = (flags & object::elf::VER_FLG_BASE) != 0;

                // Keep the base version and any versions that are referenced.
                let needed = is_base
                    || *self
                        .symbol_versions_needed
                        .get(usize::from(version_index - 1))
                        .context("Invalid version index")?;

                if needed {
                    // For the base version, we use the lib_name rather than the version name from
                    // the input file. This matches what GNU ld appears to do. Also, if we don't do
                    // this, then the C runtime hits an assertion failure, because it expects to be
                    // able to find a DT_NEEDED entry that matches the base name of a version.
                    let name = if is_base {
                        self.lib_name
                    } else {
                        // Every VERDEF entry should have at least one AUX entry.
                        let aux = aux_iterator.next()?.context("VERDEF with no AUX entry")?;
                        aux.name(e, strings)?
                    };

                    let name_size = name.len() as u64 + 1;

                    if is_base {
                        // The base version doesn't count as a version, so we don't increment
                        // version_count here. We emit it as a Verneed, whereas the actual versions
                        // are emitted as Vernaux.
                        base_size = name_size;
                    } else {
                        common.allocate(part_id::DYNSTR, name_size);
                        version_count += 1;
                    }
                }
            }

            if version_count > 0 {
                common.allocate(part_id::DYNSTR, base_size);
                common.allocate(
                    part_id::GNU_VERSION_R,
                    size_of::<crate::elf::Verneed>() as u64
                        + u64::from(version_count) * size_of::<crate::elf::Vernaux>() as u64,
                );

                self.verneed_info = Some(VerneedInfo {
                    defs,
                    string_table_index: link,
                    version_count,
                });
            }
        }

        Ok(())
    }

    /// Looks for any non-weak symbols at the same addresses as any of our copy relocations. If
    /// found, we'll generate the copy relocation for the strong symbol instead of weak symbol at
    /// the same address.
    fn select_copy_relocation_alternatives(
        &mut self,
        symbol_resolution_flags: &[AtomicResolutionFlags],
        common: &mut CommonGroupState<'data>,
        symbol_db: &SymbolDb<'data>,
    ) -> Result {
        for (i, symbol) in self.object.symbols.iter().enumerate() {
            let address = symbol.st_value(LittleEndian);
            let Some(info) = self.copy_relocations.get_mut(&address) else {
                continue;
            };

            let symbol_id = self.symbol_id_range.offset_to_id(i);

            export_dynamic(common, symbol_id, symbol_db)?;

            symbol_resolution_flags[symbol_id.as_usize()]
                .fetch_or(ResolutionFlags::COPY_RELOCATION);

            if symbol.is_weak() || !info.is_weak || info.symbol_id == symbol_id {
                continue;
            }

            info.symbol_id = symbol_id;
            info.is_weak = false;
        }

        Ok(())
    }

    fn allocate_for_copy_relocations(&self, common: &mut CommonGroupState<'data>) -> Result {
        for value in self.copy_relocations.values() {
            let symbol_id = value.symbol_id;

            let symbol = self
                .object
                .symbol(self.symbol_id_range().id_to_input(symbol_id))?;

            let section_index = symbol.st_shndx(LittleEndian);

            let section = self
                .object
                .section(SectionIndex(usize::from(section_index)))?;

            let alignment = Alignment::new(self.object.section_alignment(section)?)?;

            // Allocate space in BSS for the copy of the symbol.
            let st_size = symbol.st_size(LittleEndian);
            common.allocate(
                output_section_id::BSS.part_id_with_alignment(alignment),
                st_size,
            );

            // Allocate space required for the copy relocation itself.
            common.allocate(part_id::RELA_DYN_GENERAL, crate::elf::RELA_ENTRY_SIZE);
        }

        Ok(())
    }

    fn apply_non_addressable_indexes(
        &mut self,
        indexes: &mut NonAddressableIndexes,
        counts: &mut NonAddressableCounts,
    ) -> Result {
        self.non_addressable_indexes = *indexes;
        if let Some(info) = self.verneed_info.as_ref()
            && info.version_count > 0
        {
            counts.verneed_count += 1;
            indexes.gnu_version_r_index = indexes
                .gnu_version_r_index
                .checked_add(info.version_count)
                .context("Symbol versions overflowed 2**16")?;
        }
        Ok(())
    }

    fn finalise_layout(
        self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result<DynamicLayout<'data>> {
        let version_mapping = self.compute_version_mapping();

        let copy_relocation_symbols = self
            .copy_relocations
            .values()
            .map(|info| info.symbol_id)
            // We'll write the copy relocations in this order, so we need to sort it to ensure
            // deterministic output.
            .sorted()
            .collect_vec();

        let copy_relocation_addresses =
            self.assign_copy_relocation_addresses(&copy_relocation_symbols, memory_offsets)?;

        for (local_symbol, &resolution_flags) in self
            .object
            .symbols
            .iter()
            .zip(&resources.symbol_resolution_flags[self.symbol_id_range().as_usize()])
        {
            if resolution_flags.is_empty() {
                resolutions_out.write(None)?;
                continue;
            }

            let address;
            let dynamic_symbol_index;

            if resolution_flags.needs_copy_relocation() {
                let input_address = local_symbol.st_value(LittleEndian);

                address = *copy_relocation_addresses
                    .get(&input_address)
                    .context("Internal error: Missing copy relocation address")?;

                // Since this is a definition, the dynamic symbol index will be determined by the
                // epilogue and set by `update_dynamic_symbol_resolutions`.
                dynamic_symbol_index = None;
            } else {
                address = 0;
                let symbol_index = take_dynsym_index(memory_offsets, resources.section_layouts)?;

                dynamic_symbol_index = Some(
                    NonZeroU32::new(symbol_index)
                        .context("Tried to create dynamic symbol index 0")?,
                );
            }

            let resolution = create_resolution(
                resolution_flags,
                address,
                dynamic_symbol_index,
                ValueFlags::DYNAMIC,
                memory_offsets,
            );

            resolutions_out.write(Some(resolution))?;
        }

        if let Some(v) = self.verneed_info.as_ref() {
            memory_offsets.increment(
                part_id::GNU_VERSION_R,
                size_of::<crate::elf::Verneed>() as u64
                    + u64::from(v.version_count) * size_of::<crate::elf::Vernaux>() as u64,
            );
        }

        Ok(DynamicLayout {
            file_id: self.file_id(),
            input: self.input,
            lib_name: self.lib_name,
            object: self.object,
            symbol_id_range: self.symbol_id_range,
            input_symbol_versions: self.symbol_versions,
            copy_relocation_symbols,
            version_mapping,
            verneed_info: self.verneed_info,
            // We set this to true later for one object.
            is_last_verneed: false,
        })
    }

    /// Computes a mapping from input versions to output versions.
    fn compute_version_mapping(&self) -> Vec<u16> {
        let mut out = vec![object::elf::VER_NDX_GLOBAL; self.symbol_versions_needed.len()];
        let mut next_output_version = self.non_addressable_indexes.gnu_version_r_index;
        for (input_version, needed) in self.symbol_versions_needed.iter().enumerate() {
            if *needed {
                out[input_version] = next_output_version;
                next_output_version += 1;
            }
        }
        out
    }

    fn copy_relocate_symbol<'scope>(
        &mut self,
        symbol_id: SymbolId,
        resources: &GraphResources<'data, 'scope>,
    ) -> std::result::Result<(), Error> {
        let symbol = self
            .object
            .symbol(self.symbol_id_range().id_to_input(symbol_id))?;

        // Note, we're a shared object, so this is the address relative to the load address of the
        // shared object, not an offset within a section like with regular input objects. That means
        // that we don't need to take the section into account.
        let address = symbol.st_value(LittleEndian);

        let info = self
            .copy_relocations
            .entry(address)
            .or_insert_with(|| CopyRelocationInfo {
                symbol_id,
                is_weak: symbol.is_weak(),
            });

        info.add_symbol(symbol_id, symbol.is_weak(), resources.symbol_db);

        Ok(())
    }

    fn assign_copy_relocation_addresses(
        &self,
        copy_relocation_symbols: &[SymbolId],
        memory_offsets: &mut OutputSectionPartMap<u64>,
    ) -> Result<HashMap<u64, u64>> {
        copy_relocation_symbols
            .iter()
            .map(|symbol_id| {
                let symbol = self
                    .object
                    .symbol(self.symbol_id_range.id_to_input(*symbol_id))?;

                let input_address = symbol.st_value(LittleEndian);

                let output_address =
                    assign_copy_relocation_address(self.object, symbol, memory_offsets)?;

                Ok((input_address, output_address))
            })
            .try_collect()
    }

    /// Return whether all DT_NEEDED entries for this shared object correspond to input files that
    /// we have loaded.
    fn has_complete_deps(&self, resources: &GraphResources) -> bool {
        let Ok(dynamic_tags) = self.object.dynamic_tags() else {
            return true;
        };

        let e = LittleEndian;
        for entry in dynamic_tags {
            let value = entry.d_val(e);
            match entry.d_tag(e) as u32 {
                object::elf::DT_NEEDED => {
                    let Ok(name) = self.object.symbols.strings().get(value as u32) else {
                        return false;
                    };
                    if !resources.input_data.has_file(name) {
                        return false;
                    }
                }
                _ => {}
            }
        }

        true
    }
}

impl<'data> LinkerScriptLayoutState<'data> {
    fn finalise_layout(
        &self,
        memory_offsets: &mut OutputSectionPartMap<u64>,
        resolutions_out: &mut ResolutionWriter,
        resources: &FinaliseLayoutResources<'_, 'data>,
    ) -> Result {
        self.internal_symbols
            .finalise_layout(memory_offsets, resolutions_out, resources)
    }

    fn new(input: ResolvedLinkerScript<'data>) -> Self {
        Self {
            file_id: input.file_id,
            input: input.input,
            symbol_id_range: input.symbol_id_range,
            internal_symbols: InternalSymbols {
                symbol_definitions: input.symbol_definitions,
                start_symbol_id: input.symbol_id_range.start(),
            },
        }
    }

    fn activate(
        &self,
        common: &mut CommonGroupState<'data>,
        resources: &GraphResources<'data, '_>,
    ) -> Result {
        for offset in 0..self.symbol_id_range.len() {
            let symbol_id = self.symbol_id_range.offset_to_id(offset);
            resources.symbol_resolution_flags[symbol_id.as_usize()]
                .fetch_or(ResolutionFlags::EXPORT_DYNAMIC);

            if resources.symbol_db.args.needs_dynsym() {
                export_dynamic(common, symbol_id, resources.symbol_db)?;
            }
        }

        Ok(())
    }

    fn finalise_sizes(
        &self,
        common: &mut CommonGroupState<'data>,
        symbol_db: &SymbolDb<'data>,
        symbol_resolution_flags: &[AtomicResolutionFlags],
    ) -> Result {
        self.internal_symbols.allocate_symbol_table_sizes(
            &mut common.mem_sizes,
            symbol_db,
            |symbol_id, _info| {
                !symbol_resolution_flags[symbol_id.as_usize()]
                    .get()
                    .is_empty()
            },
        )?;

        Ok(())
    }
}

impl CopyRelocationInfo {
    fn add_symbol(&mut self, symbol_id: SymbolId, is_weak: bool, symbol_db: &SymbolDb) {
        if self.symbol_id == symbol_id || is_weak {
            return;
        }

        if !self.is_weak {
            warning(&format!(
                "Multiple non-weak symbols at the same address have copy relocations: {}, {}",
                symbol_db.symbol_debug(self.symbol_id),
                symbol_db.symbol_debug(symbol_id)
            ));
        }

        self.symbol_id = symbol_id;
        self.is_weak = false;
    }
}

/// Assigns the address in BSS for the copy relocation of a symbol.
fn assign_copy_relocation_address(
    file: &File,
    local_symbol: &object::elf::Sym64<LittleEndian>,
    memory_offsets: &mut OutputSectionPartMap<u64>,
) -> Result<u64, Error> {
    let section_index = local_symbol.st_shndx(LittleEndian);
    let section = file.section(SectionIndex(usize::from(section_index)))?;
    let alignment = Alignment::new(file.section_alignment(section)?)?;
    let bss = memory_offsets.get_mut(output_section_id::BSS.part_id_with_alignment(alignment));
    let a = *bss;
    *bss += local_symbol.st_size(LittleEndian);
    Ok(a)
}

#[derive(Default)]
struct DynamicTagValues<'data> {
    verdefnum: u64,
    soname: Option<&'data [u8]>,
}

impl<'data> DynamicTagValues<'data> {
    fn read(file: &File<'data>) -> Result<Self> {
        let mut values = DynamicTagValues::default();
        let Ok(dynamic_tags) = file.dynamic_tags() else {
            return Ok(values);
        };
        let e = LittleEndian;
        for entry in dynamic_tags {
            let value = entry.d_val(e);
            match entry.d_tag(e) as u32 {
                object::elf::DT_VERDEFNUM => {
                    values.verdefnum = value;
                }
                object::elf::DT_SONAME => {
                    values.soname = Some(
                        file.symbols
                            .strings()
                            .get(value as u32)
                            .map_err(|()| error!("Invalid DT_SONAME 0x{value:x}"))?,
                    );
                }
                _ => {}
            }
        }
        Ok(values)
    }
}

fn take_dynsym_index(
    memory_offsets: &mut OutputSectionPartMap<u64>,
    section_layouts: &OutputSectionMap<OutputRecordLayout>,
) -> Result<u32> {
    let index = u32::try_from(
        (memory_offsets.get(part_id::DYNSYM)
            - section_layouts.get(output_section_id::DYNSYM).mem_offset)
            / crate::elf::SYMTAB_ENTRY_SIZE,
    )
    .context("Too many dynamic symbols")?;
    memory_offsets.increment(part_id::DYNSYM, crate::elf::SYMTAB_ENTRY_SIZE);
    Ok(index)
}

impl Layout<'_> {
    pub(crate) fn mem_address_of_built_in(&self, section_id: OutputSectionId) -> u64 {
        self.section_layouts.get(section_id).mem_offset
    }
}

impl std::fmt::Debug for FileLayoutState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileLayoutState::Object(s) => f.debug_tuple("Object").field(&s.input).finish(),
            FileLayoutState::Prelude(_) => f.debug_tuple("Internal").finish(),
            FileLayoutState::Dynamic(s) => f.debug_tuple("Dynamic").field(&s.input).finish(),
            FileLayoutState::LinkerScript(s) => {
                f.debug_tuple("LinkerScript").field(&s.input).finish()
            }
            FileLayoutState::NotLoaded(_) => Display::fmt(&"<not loaded>", f),
            FileLayoutState::Epilogue(_) => Display::fmt(&"<custom sections>", f),
        }
    }
}

fn section_debug(object: &crate::elf::File, section_index: object::SectionIndex) -> SectionDebug {
    let name = object
        .section(section_index)
        .and_then(|section| object.section_name(section))
        .map_or_else(
            |_| "??".to_owned(),
            |name| String::from_utf8_lossy(name).into_owned(),
        );
    SectionDebug { name }
}

struct SectionDebug {
    name: String,
}

impl Display for SectionDebug {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "`{}`", self.name)
    }
}

impl GnuHashLayout {
    pub(crate) fn bucket_for_hash(&self, hash: u32) -> u32 {
        hash % self.bucket_count
    }
}

impl<'data> DynamicSymbolDefinition<'data> {
    fn new(symbol_id: SymbolId, name: &'data [u8], version: u16) -> Self {
        Self {
            symbol_id,
            name,
            hash: gnu_hash(name),
            version,
        }
    }
}

impl SectionLoadRequest {
    fn new(file_id: FileId, section_index: SectionIndex) -> Self {
        Self {
            file_id,
            section_index: section_index.0 as u32,
        }
    }

    fn section_index(self) -> SectionIndex {
        SectionIndex(self.section_index as usize)
    }
}

fn needs_tlsld(relocation_kind: RelocationKind) -> bool {
    matches!(
        relocation_kind,
        RelocationKind::TlsLd | RelocationKind::TlsLdGot | RelocationKind::TlsLdGotBase
    )
}

impl<'data> ObjectLayout<'data> {
    pub(crate) fn relocations(&self, index: SectionIndex) -> Result<RelocationList<'data>> {
        self.object.relocations(index, &self.relocations)
    }
}

/// Performs layout of sections and segments then makes sure that the loadable segments don't
/// overlap and that sections don't overlap.
#[test]
fn test_no_disallowed_overlaps() {
    use crate::output_section_id::OrderEvent;

    let mut output_sections = OutputSections::with_base_address(0x1000);
    let (output_order, program_segments) = output_sections.output_order();
    let args = Args::default();
    let section_part_sizes = output_sections.new_part_map::<u64>().map(|_, _| 7);

    let section_part_layouts = layout_section_parts(
        &section_part_sizes,
        &output_sections,
        &program_segments,
        &output_order,
        &args,
    );

    let section_layouts = layout_sections(&output_sections, &section_part_layouts);

    // Make sure no alloc sections overlap
    let mut last_file_start = 0;
    let mut last_mem_start = 0;
    let mut last_file_end = 0;
    let mut last_mem_end = 0;
    let mut last_section_id = output_section_id::FILE_HEADER;

    for event in &output_order {
        let OrderEvent::Section(section_id) = event else {
            continue;
        };

        let section_flags = output_sections.section_flags(section_id);
        if !section_flags.contains(shf::ALLOC) {
            return;
        }

        let section = section_layouts.get(section_id);
        let mem_offset = section.mem_offset;
        let mem_end = mem_offset + section.mem_size;
        assert!(
            mem_offset >= last_mem_end,
            "Memory sections: {last_section_id} @{last_mem_start:x}..{last_mem_end:x} overlaps {section_id} @{mem_offset:x}..{mem_end:x}",
        );
        let file_offset = section.file_offset;
        let file_end = file_offset + section.file_size;
        assert!(
            file_offset >= last_file_end,
            "File sections {last_section_id} @{last_file_start:x}..{last_file_end} {section_id} @{file_offset:x}..{file_end:x}",
        );
        last_mem_start = mem_offset;
        last_file_start = file_offset;
        last_mem_end = mem_end;
        last_file_end = file_end;
        last_section_id = section_id;
    }

    let header_info = HeaderInfo {
        num_output_sections_with_content: 0,
        active_segment_ids: (0..program_segments.len())
            .map(ProgramSegmentId::new)
            .collect(),
        eflags: 0,
    };

    let mut section_index = 0;
    output_sections.section_infos.for_each(|_, info| {
        if info.section_flags.contains(shf::ALLOC) {
            output_sections
                .output_section_indexes
                .push(Some(section_index));
            section_index += 1;
        } else {
            output_sections.output_section_indexes.push(None);
        }
    });

    let segment_layouts = compute_segment_layout(
        &section_layouts,
        &output_sections,
        &output_order,
        &program_segments,
        &header_info,
    )
    .unwrap();

    // Make sure loadable segments don't overlap in memory or in the file.
    let mut last_file = 0;
    let mut last_mem = 0;
    for seg_layout in &segment_layouts.segments {
        let seg_id = seg_layout.id;
        if program_segments.is_load_segment(seg_id) {
            continue;
        }
        assert!(
            seg_layout.sizes.mem_offset >= last_mem,
            "Overlapping memory segment: {} < {}",
            last_mem,
            seg_layout.sizes.mem_offset,
        );
        assert!(
            seg_layout.sizes.file_offset >= last_file,
            "Overlapping file segment {} < {}",
            last_file,
            seg_layout.sizes.file_offset,
        );
        last_mem = seg_layout.sizes.mem_offset + seg_layout.sizes.mem_size;
        last_file = seg_layout.sizes.file_offset + seg_layout.sizes.file_size;
    }
}

impl Display for ResolutionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

pub(crate) struct ResFlagsDisplay<'a>(pub(crate) &'a Resolution);

impl Display for ResFlagsDisplay<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "value_flags = {} resolution_flags = {}",
            self.0.value_flags, self.0.resolution_flags
        )
    }
}

/// Verifies that we allocate and use consistent amounts of various output sections for the supplied
/// combination of flags and output kind. If this function returns an error, then we would have
/// failed during writing anyway. By failing now, we can report the particular combination of inputs
/// that caused the failure.
fn verify_consistent_allocation_handling(
    value_flags: ValueFlags,
    resolution_flags: ResolutionFlags,
    output_kind: OutputKind,
) -> Result {
    let output_sections = OutputSections::with_base_address(0);
    let (output_order, _program_segments) = output_sections.output_order();
    let mut mem_sizes = output_sections.new_part_map();
    let resolution_flags = AtomicResolutionFlags::new(resolution_flags);
    allocate_symbol_resolution(value_flags, &resolution_flags, &mut mem_sizes, output_kind);
    let resolution_flags = resolution_flags.get();
    let mut memory_offsets = output_sections.new_part_map();
    *memory_offsets.get_mut(part_id::GOT) = 0x10;
    *memory_offsets.get_mut(part_id::PLT_GOT) = 0x10;
    let has_dynamic_symbol = value_flags.is_dynamic()
        || (resolution_flags.needs_export_dynamic() && value_flags.is_interposable());
    let dynamic_symbol_index = has_dynamic_symbol.then(|| NonZeroU32::new(1).unwrap());

    let resolution = create_resolution(
        resolution_flags,
        0,
        dynamic_symbol_index,
        value_flags,
        &mut memory_offsets,
    );

    elf_writer::verify_resolution_allocation(
        &output_sections,
        &output_order,
        output_kind,
        &mem_sizes,
        &resolution,
    )
    .with_context(|| {
        format!(
            "Inconsistent allocation detected. \
             output_kind={output_kind:?} \
             value_flags={value_flags} \
             resolution_flags={resolution_flags} \
             has_dynamic_symbol={has_dynamic_symbol:?}"
        )
    })?;

    Ok(())
}

pub(crate) struct VersionDef {
    pub(crate) name: Vec<u8>,
    pub(crate) parent_index: Option<u16>,
}
