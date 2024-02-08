use crate::alignment;
use crate::alignment::Alignment;
use crate::elf;
use crate::elf::Section;
use crate::error::Result;
use crate::layout::Layout;
use crate::program_segments::ProgramSegmentId;
use ahash::AHashMap;
use anyhow::anyhow;
use anyhow::bail;
use core::mem::size_of;
use object::ObjectSection;
use std::collections::BTreeMap;
use std::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TemporaryOutputSectionId<'data> {
    BuiltIn(OutputSectionId),
    Custom(CustomSectionId<'data>),
    EhFrameData,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutputSectionId(u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct CustomSectionId<'data> {
    pub(crate) name: &'data [u8],
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UnloadedSection<'data> {
    pub(crate) output_section_id: TemporaryOutputSectionId<'data>,
    pub(crate) details: SectionDetails<'data>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SectionDetails<'data> {
    pub(crate) name: &'data [u8],
    pub(crate) ty: elf::Sht,
    pub(crate) section_flags: u64,
    pub(crate) element_size: u64,

    /// Whether this section should always be linked, even if it's not referenced.
    pub(crate) retain: bool,

    /// In a "packed" section, no padding will be added for alignment purposes.
    pub(crate) packed: bool,
}

// Sections that we generate ourselves rather than copying directly from input objects.
pub(crate) const HEADERS: OutputSectionId = OutputSectionId(0);
pub(crate) const SHSTRTAB: OutputSectionId = OutputSectionId(1);
pub(crate) const SYMTAB: OutputSectionId = OutputSectionId(2);
pub(crate) const STRTAB: OutputSectionId = OutputSectionId(3);
pub(crate) const GOT: OutputSectionId = OutputSectionId(4);
pub(crate) const PLT: OutputSectionId = OutputSectionId(5);
pub(crate) const RELA_PLT: OutputSectionId = OutputSectionId(6);
pub(crate) const EH_FRAME: OutputSectionId = OutputSectionId(7);
pub(crate) const EH_FRAME_HDR: OutputSectionId = OutputSectionId(8);

/// Regular sections are sections that come from input files and can contain a mix of alignments.
pub(crate) const NUM_GENERATED_SECTIONS: usize = 9;

// Sections that need to be referenced from code. When adding new sections here, be sure to update
// `test_constant_ids`.
pub(crate) const RODATA: OutputSectionId = OutputSectionId::regular(0);
pub(crate) const INIT_ARRAY: OutputSectionId = OutputSectionId::regular(1);
pub(crate) const FINI_ARRAY: OutputSectionId = OutputSectionId::regular(2);
pub(crate) const PREINIT_ARRAY: OutputSectionId = OutputSectionId::regular(3);
pub(crate) const TEXT: OutputSectionId = OutputSectionId::regular(4);
pub(crate) const INIT: OutputSectionId = OutputSectionId::regular(5);
pub(crate) const FINI: OutputSectionId = OutputSectionId::regular(6);
pub(crate) const DATA: OutputSectionId = OutputSectionId::regular(7);
pub(crate) const TDATA: OutputSectionId = OutputSectionId::regular(8);
pub(crate) const TBSS: OutputSectionId = OutputSectionId::regular(9);
pub(crate) const BSS: OutputSectionId = OutputSectionId::regular(10);

// pub(crate) const DYNAMIC: BuiltInId = BuiltInId(13);
// pub(crate) const DYNSTR: BuiltInId = BuiltInId(14);

/// How many built-in sections we define. These are regular sections plus sections that we generate
/// like GOT, PLT, STRTAB etc. This doesn't include custom sections.
pub(crate) const NUM_BUILT_IN_SECTIONS: usize = NUM_GENERATED_SECTIONS + 11;

pub(crate) struct OutputSections<'data> {
    pub(crate) section_infos: Vec<SectionOutputInfo<'data>>,
    custom_by_name: AHashMap<&'data [u8], OutputSectionId>,
    pub(crate) ro_custom: Vec<OutputSectionId>,
    pub(crate) exec_custom: Vec<OutputSectionId>,
    pub(crate) data_custom: Vec<OutputSectionId>,
    pub(crate) bss_custom: Vec<OutputSectionId>,
}

pub(crate) struct SectionOutputInfo<'data> {
    pub(crate) output_index: u16,
    pub(crate) loadable_segment_id: ProgramSegmentId,
    pub(crate) details: SectionDetails<'data>,
}

pub(crate) struct BuiltInSectionDetails {
    details: SectionDetails<'static>,
    pub(crate) link: Option<OutputSectionId>,
    pub(crate) start_symbol_name: Option<&'static str>,
    pub(crate) end_symbol_name: Option<&'static str>,
    pub(crate) min_alignment: Alignment,
    info_fn: Option<fn(&Layout) -> u32>,
}

impl SectionDetails<'static> {
    const fn default() -> Self {
        Self {
            name: &[],
            ty: elf::Sht::Null,
            section_flags: elf::shf::ALLOC,
            retain: false,
            element_size: 0,
            packed: false,
        }
    }
}

const DEFAULT_DEFS: BuiltInSectionDetails = BuiltInSectionDetails {
    details: SectionDetails {
        name: &[],
        packed: false,
        ..SectionDetails::default()
    },
    link: None,
    start_symbol_name: None,
    end_symbol_name: None,
    min_alignment: alignment::MIN,
    info_fn: None,
};

const SECTION_DEFINITIONS: [BuiltInSectionDetails; NUM_BUILT_IN_SECTIONS] = [
    // A section into which we write headers.
    BuiltInSectionDetails {
        details: SectionDetails {
            name: "".as_bytes(),
            section_flags: 0,
            ..SectionDetails::default()
        },
        start_symbol_name: Some("__ehdr_start"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".shstrtab".as_bytes(),
            ty: elf::Sht::Strtab,
            section_flags: elf::shf::STRINGS,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".symtab".as_bytes(),
            ty: elf::Sht::Symtab,
            element_size: size_of::<elf::SymtabEntry>() as u64,
            ..SectionDetails::default()
        },
        min_alignment: alignment::SYMTAB_ENTRY,
        link: Some(STRTAB),
        info_fn: Some(symtab_info),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".strtab".as_bytes(),
            ty: elf::Sht::Strtab,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".got".as_bytes(),
            ty: elf::Sht::Progbits,
            ..SectionDetails::default()
        },
        start_symbol_name: Some("_GLOBAL_OFFSET_TABLE_"),
        min_alignment: alignment::GOT_ENTRY,
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".plt".as_bytes(),
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC | elf::shf::EXECINSTR,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".rela.plt".as_bytes(),
            ty: elf::Sht::Rela,
            section_flags: elf::shf::ALLOC,
            element_size: elf::RELA_ENTRY_SIZE,
            ..SectionDetails::default()
        },
        min_alignment: alignment::RELA_ENTRY,
        start_symbol_name: Some("__rela_iplt_start"),
        end_symbol_name: Some("__rela_iplt_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".eh_frame".as_bytes(),
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC | elf::shf::WRITE,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".eh_frame_hdr".as_bytes(),
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC,
            ..SectionDetails::default()
        },
        min_alignment: alignment::USIZE,
        ..DEFAULT_DEFS
    },
    // Start of regular sections
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".rodata".as_bytes(),
            ty: elf::Sht::Progbits,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".init_array".as_bytes(),
            ty: elf::Sht::InitArray,
            retain: true,
            ..SectionDetails::default()
        },
        start_symbol_name: Some("__init_array_start"),
        end_symbol_name: Some("__init_array_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".fini_array".as_bytes(),
            ty: elf::Sht::FiniArray,
            retain: true,
            ..SectionDetails::default()
        },
        start_symbol_name: Some("__fini_array_start"),
        end_symbol_name: Some("__fini_array_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".preinit_array".as_bytes(),
            ty: elf::Sht::PreinitArray,
            retain: true,
            ..SectionDetails::default()
        },
        start_symbol_name: Some("__preinit_array_start"),
        end_symbol_name: Some("__preinit_array_end"),
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".text".as_bytes(),
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC | elf::shf::EXECINSTR,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".init".as_bytes(),
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC | elf::shf::EXECINSTR,
            retain: true,
            packed: true,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".fini".as_bytes(),
            retain: true,
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC | elf::shf::EXECINSTR,
            packed: true,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".data".as_bytes(),
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC | elf::shf::WRITE,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".tdata".as_bytes(),
            ty: elf::Sht::Progbits,
            section_flags: elf::shf::ALLOC | elf::shf::TLS,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".tbss".as_bytes(),
            ty: elf::Sht::Nobits,
            section_flags: elf::shf::ALLOC | elf::shf::TLS,
            ..SectionDetails::default()
        },
        ..DEFAULT_DEFS
    },
    BuiltInSectionDetails {
        details: SectionDetails {
            name: ".bss".as_bytes(),
            ty: elf::Sht::Nobits,
            section_flags: elf::shf::ALLOC | elf::shf::WRITE,
            ..SectionDetails::default()
        },
        end_symbol_name: Some("_end"),
        ..DEFAULT_DEFS
    },
    // OutputSectionDef {
    //     name: ".dynamic",
    //     ty: elf::Sht::Dynamic,
    //     segment_type: SegmentType::Dynamic,
    //     indexing: SectionIndexing::element::<elf::DynamicEntry>(),
    //     link: Some(DYNSTR),
    //     ..DEFAULT_DEFS
    // },
    // OutputSectionDef {
    //     name: ".dynstr",
    //     ty: elf::Sht::Strtab,
    //     indexing: SectionIndexing::indexed(1),
    //     ..DEFAULT_DEFS
    // },
];

impl<'data> UnloadedSection<'data> {
    pub(crate) fn from_section(section: &Section<'data, '_>) -> Result<Option<Self>> {
        // Ideally we support reading an actual linker script to make these decisions, but for now
        // we just hard code stuff.
        let section_name = section.name_bytes().unwrap_or_default();
        let built_in_id = if section_name.starts_with(b".rodata") {
            Some(RODATA)
        } else if section_name.starts_with(b".text") {
            Some(TEXT)
        } else if section_name.starts_with(b".data") {
            Some(DATA)
        } else if section_name.starts_with(b".bss") {
            Some(BSS)
        } else if section_name.starts_with(b".init_array") || section_name.starts_with(b".ctors.") {
            Some(INIT_ARRAY)
        } else if section_name.starts_with(b".fini_array") || section_name.starts_with(b".dtors.") {
            Some(FINI_ARRAY)
        } else if section_name == b".init" {
            Some(INIT)
        } else if section_name == b".fini" {
            Some(FINI)
        } else if section_name == b".preinit_array" {
            Some(PREINIT_ARRAY)
        } else if section_name.starts_with(b".tdata") {
            Some(TDATA)
        } else if section_name.starts_with(b".tbss") {
            Some(TBSS)
        } else if section_name == b".eh_frame" {
            return Ok(Some(UnloadedSection {
                output_section_id: TemporaryOutputSectionId::EhFrameData,
                details: EH_FRAME.built_in_details().details,
            }));
        } else {
            let mut retain = false;
            let mut section_flags = 0;
            let ty = match section.kind() {
                object::SectionKind::UninitializedData | object::SectionKind::UninitializedTls => {
                    crate::elf::Sht::Nobits
                }
                _ => crate::elf::Sht::Progbits,
            };
            if let object::SectionFlags::Elf { sh_flags } = section.flags() {
                retain = sh_flags & crate::elf::shf::GNU_RETAIN != 0;
                section_flags = sh_flags;
            }
            if !section_name.is_empty() && !section_name.starts_with(b".") {
                return Ok(Some(UnloadedSection {
                    output_section_id: TemporaryOutputSectionId::Custom(CustomSectionId {
                        name: section_name,
                    }),
                    details: SectionDetails {
                        name: section_name,
                        ty,
                        section_flags,
                        element_size: 0,
                        retain,
                        packed: false,
                    },
                }));
            }
            match section.kind() {
                object::SectionKind::Text => Some(TEXT),
                object::SectionKind::ReadOnlyData => Some(RODATA),
                object::SectionKind::Data => Some(DATA),
                object::SectionKind::UninitializedData => Some(BSS),
                object::SectionKind::Tls => Some(TDATA),
                object::SectionKind::UninitializedTls => Some(TBSS),
                object::SectionKind::ReadOnlyString => Some(RODATA),

                // TODO: Do we need to place these?
                object::SectionKind::OtherString => None,
                _ => None,
            }
        };
        let Some(built_in_id) = built_in_id else {
            return Ok(None);
        };
        Ok(Some(UnloadedSection {
            output_section_id: TemporaryOutputSectionId::BuiltIn(built_in_id),
            details: built_in_id.built_in_details().details,
        }))
    }
}

pub(crate) fn built_in_section_ids(
) -> impl ExactSizeIterator<Item = OutputSectionId> + DoubleEndedIterator<Item = OutputSectionId> {
    (0..NUM_BUILT_IN_SECTIONS).map(|n| OutputSectionId(n as u16))
}

impl OutputSectionId {
    const fn regular(offset: u16) -> OutputSectionId {
        OutputSectionId(NUM_GENERATED_SECTIONS as u16 + offset)
    }

    pub(crate) fn from_usize(raw: usize) -> Self {
        OutputSectionId(raw as u16)
    }

    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }

    pub(crate) fn built_in_details(self) -> &'static BuiltInSectionDetails {
        &SECTION_DEFINITIONS[self.as_usize()]
    }

    fn event(self) -> OrderEvent<'static> {
        OrderEvent::Section(self, &SECTION_DEFINITIONS[self.as_usize()].details)
    }

    pub(crate) fn min_alignment(&self) -> Alignment {
        SECTION_DEFINITIONS
            .get(self.as_usize())
            .map(|d| d.min_alignment)
            .unwrap_or(alignment::MIN)
    }

    /// Computes the value for the info field for this section. For most sections this is just 0,
    /// but a few sections put some special value in there.
    pub(crate) fn info(&self, layout: &Layout) -> u32 {
        SECTION_DEFINITIONS
            .get(self.as_usize())
            .and_then(|d| d.info_fn)
            .map(|info_fn| (info_fn)(layout))
            .unwrap_or(0)
    }
}

pub(crate) enum OrderEvent<'data> {
    SegmentStart(ProgramSegmentId),
    SegmentEnd(ProgramSegmentId),
    Section(OutputSectionId, &'data SectionDetails<'data>),
}

#[derive(Default)]
pub(crate) struct OutputSectionsBuilder<'data> {
    custom: BTreeMap<&'data [u8], SectionDetails<'data>>,
}

impl<'data> OutputSectionsBuilder<'data> {
    pub(crate) fn build(self) -> Result<OutputSections<'data>> {
        let mut section_infos: Vec<_> = SECTION_DEFINITIONS
            .iter()
            .map(|d| SectionOutputInfo {
                details: d.details,
                output_index: 0,
                loadable_segment_id: crate::program_segments::LOAD_RO,
            })
            .collect();
        let mut ro_custom = Vec::new();
        let mut exec_custom = Vec::new();
        let mut data_custom = Vec::new();
        let mut bss_custom = Vec::new();
        let custom_by_name = self
            .custom
            .iter()
            .enumerate()
            .map(|(offset, (name, details))| {
                section_infos.push(SectionOutputInfo {
                    details: *details,
                    // We'll fill in the following fields properly below.
                    output_index: 0,
                    loadable_segment_id: crate::program_segments::LOAD_RO,
                });
                let id = OutputSectionId::from_usize(offset + NUM_BUILT_IN_SECTIONS);
                if (details.section_flags & crate::elf::shf::EXECINSTR) != 0 {
                    exec_custom.push(id);
                } else if (details.section_flags & crate::elf::shf::WRITE) == 0 {
                    ro_custom.push(id)
                } else if details.ty == crate::elf::Sht::Nobits {
                    bss_custom.push(id);
                } else {
                    data_custom.push(id);
                }
                (*name, id)
            })
            .collect();

        let mut output_sections = OutputSections {
            section_infos,
            custom_by_name,
            ro_custom,
            exec_custom,
            data_custom,
            bss_custom,
        };
        let mut extra = vec![None; output_sections.section_infos.len()];
        let mut load_seg_id = None;
        let mut output_index = 0;
        output_sections.sections_and_segments_do(|event| match event {
            OrderEvent::SegmentStart(seg_id) => {
                if seg_id.segment_type() == crate::elf::SegmentType::Load {
                    load_seg_id = Some(seg_id);
                }
            }
            OrderEvent::SegmentEnd(seg_id) => {
                if load_seg_id == Some(seg_id) {
                    load_seg_id = None;
                }
            }
            OrderEvent::Section(section_id, _section_details) => {
                extra[section_id.as_usize()] = Some((output_index, load_seg_id));
                output_index += 1;
            }
        });
        extra
            .iter()
            .zip(output_sections.section_infos.iter_mut())
            .try_for_each(|(ext, info)| -> Result {
                let (output_index, load_seg_id) = ext.ok_or_else(|| {
                    anyhow!(
                        "Section `{}` is missing from output order (update sections_and_segments_do)",
                        String::from_utf8_lossy(info.details.name),
                    )
                })?;
                info.loadable_segment_id = load_seg_id
                    .ok_or_else(|| anyhow!("A section is not allocated to any loadable segment"))?;
                info.output_index = output_index;
                Ok(())
            })?;
        Ok(output_sections)
    }

    pub(crate) fn add_sections(
        &mut self,
        custom_sections: &[(object::SectionIndex, SectionDetails<'data>)],
    ) -> Result {
        use std::collections::btree_map::Entry;

        for (_, details) in custom_sections {
            match self.custom.entry(details.name) {
                Entry::Occupied(e) => {
                    if e.get() != details {
                        bail!(
                            "Inconsistent attributes for {}: {:?} vs {:?}",
                            String::from_utf8_lossy(details.name),
                            e.get(),
                            details,
                        );
                    }
                }
                Entry::Vacant(e) => {
                    e.insert(*details);
                }
            }
        }
        Ok(())
    }
}

impl<'data> OutputSections<'data> {
    /// Calls `cb` for each section and segment in output order. Segments span multiple sections and
    /// can overlap, so are represented as start and end events.
    pub(crate) fn sections_and_segments_do(&self, mut cb: impl FnMut(OrderEvent)) {
        cb(OrderEvent::SegmentStart(crate::program_segments::LOAD_RO));
        cb(HEADERS.event());
        cb(RODATA.event());
        cb(OrderEvent::SegmentStart(crate::program_segments::EH_FRAME));
        cb(EH_FRAME_HDR.event());
        cb(OrderEvent::SegmentEnd(crate::program_segments::EH_FRAME));
        cb(INIT_ARRAY.event());
        cb(FINI_ARRAY.event());
        cb(PREINIT_ARRAY.event());
        cb(SHSTRTAB.event());
        cb(SYMTAB.event());
        cb(STRTAB.event());
        cb(RELA_PLT.event());
        self.ids_do(&self.ro_custom, &mut cb);
        cb(OrderEvent::SegmentEnd(crate::program_segments::LOAD_RO));

        cb(OrderEvent::SegmentStart(crate::program_segments::LOAD_EXEC));
        cb(PLT.event());
        cb(TEXT.event());
        cb(INIT.event());
        cb(FINI.event());
        self.ids_do(&self.exec_custom, &mut cb);
        cb(OrderEvent::SegmentEnd(crate::program_segments::LOAD_EXEC));

        cb(OrderEvent::SegmentStart(crate::program_segments::LOAD_RW));
        cb(GOT.event());
        cb(DATA.event());
        cb(EH_FRAME.event());
        self.ids_do(&self.data_custom, &mut cb);
        cb(OrderEvent::SegmentStart(crate::program_segments::TLS));
        cb(TDATA.event());
        cb(TBSS.event());
        cb(OrderEvent::SegmentEnd(crate::program_segments::TLS));
        cb(BSS.event());
        self.ids_do(&self.bss_custom, &mut cb);
        cb(OrderEvent::SegmentEnd(crate::program_segments::LOAD_RW));
    }

    fn ids_do(&self, ids: &Vec<OutputSectionId>, cb: &mut impl FnMut(OrderEvent<'_>)) {
        for id in ids {
            (*cb)(OrderEvent::Section(
                *id,
                &self.section_infos[id.as_usize()].details,
            ));
        }
    }

    /// Calls `cb` for each section in output order.
    pub(crate) fn sections_do(&self, mut cb: impl FnMut(OutputSectionId, &'_ SectionDetails)) {
        self.sections_and_segments_do(|event| {
            if let OrderEvent::Section(id, details) = event {
                cb(id, details);
            }
        });
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.section_infos.len()
    }

    pub(crate) fn has_data_in_file(&self, id: OutputSectionId) -> bool {
        self.output_info(id).details.has_data_in_file()
    }

    pub(crate) fn output_info(&self, id: OutputSectionId) -> &SectionOutputInfo {
        &self.section_infos[id.as_usize()]
    }

    /// Returns the output index of the built-in-section `id`.
    pub(crate) fn index_of_built_in(&self, id: OutputSectionId) -> u16 {
        self.section_infos[id.as_usize()].output_index
    }

    pub(crate) fn loadable_segment_id_for(&self, id: OutputSectionId) -> ProgramSegmentId {
        self.output_info(id).loadable_segment_id
    }

    pub(crate) fn details(&self, id: OutputSectionId) -> &SectionDetails {
        &self.output_info(id).details
    }

    pub(crate) fn link_id(&self, section_id: OutputSectionId) -> Option<OutputSectionId> {
        SECTION_DEFINITIONS
            .get(section_id.as_usize())
            .and_then(|def| def.link)
    }

    pub(crate) fn name(&self, section_id: OutputSectionId) -> &[u8] {
        self.section_infos[section_id.as_usize()].details.name
    }

    pub(crate) fn custom_name_to_id(&self, name: &[u8]) -> Option<OutputSectionId> {
        self.custom_by_name.get(name).cloned()
    }

    #[cfg(test)]
    pub(crate) fn for_testing() -> OutputSections<'static> {
        let mut builder = OutputSectionsBuilder::default();
        let section_details = SectionDetails {
            name: b"ro",
            ty: crate::elf::Sht::Progbits,
            section_flags: 0,
            element_size: 0,
            retain: true,
            packed: false,
        };
        builder
            .add_sections(&[
                (object::SectionIndex(0), section_details),
                (
                    object::SectionIndex(0),
                    SectionDetails {
                        name: b"exec",
                        section_flags: crate::elf::shf::EXECINSTR,
                        ..section_details
                    },
                ),
                (
                    object::SectionIndex(0),
                    SectionDetails {
                        name: b"data",
                        section_flags: crate::elf::shf::WRITE,
                        ..section_details
                    },
                ),
                (
                    object::SectionIndex(0),
                    SectionDetails {
                        name: b"bss",
                        ty: crate::elf::Sht::Nobits,
                        ..section_details
                    },
                ),
            ])
            .unwrap();
        builder.build().unwrap()
    }
}

impl<'data> SectionDetails<'data> {
    pub(crate) fn has_data_in_file(&self) -> bool {
        self.ty != elf::Sht::Nobits
    }
}

fn symtab_info(layout: &Layout) -> u32 {
    // For SYMTAB, the info field holds the index of the first non-local symbol.
    (layout.section_part_layouts.symtab_locals.file_size / size_of::<elf::SymtabEntry>()) as u32
}

#[test]
fn test_constant_ids() {
    let check = &[
        (HEADERS, ""),
        (RODATA, ".rodata"),
        (TEXT, ".text"),
        (INIT_ARRAY, ".init_array"),
        (FINI_ARRAY, ".fini_array"),
        (PREINIT_ARRAY, ".preinit_array"),
        (DATA, ".data"),
        (EH_FRAME, ".eh_frame"),
        (EH_FRAME_HDR, ".eh_frame_hdr"),
        (SHSTRTAB, ".shstrtab"),
        (SYMTAB, ".symtab"),
        (STRTAB, ".strtab"),
        (TDATA, ".tdata"),
        (TBSS, ".tbss"),
        (BSS, ".bss"),
        (GOT, ".got"),
        (PLT, ".plt"),
        (INIT, ".init"),
        (FINI, ".fini"),
        (RELA_PLT, ".rela.plt"),
    ];
    for (id, name) in check {
        assert_eq!(
            std::str::from_utf8(SECTION_DEFINITIONS[id.as_usize()].details.name).unwrap(),
            *name
        );
    }
    assert_eq!(NUM_BUILT_IN_SECTIONS, check.len());
}

impl std::fmt::Display for OutputSectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.as_usize(), f)
    }
}

impl<'data> std::fmt::Display for TemporaryOutputSectionId<'data> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TemporaryOutputSectionId::BuiltIn(id) => {
                write!(
                    f,
                    "section #{} ({})",
                    id.as_usize(),
                    String::from_utf8_lossy(SECTION_DEFINITIONS[id.as_usize()].details.name)
                )
            }
            TemporaryOutputSectionId::Custom(custom) => {
                write!(
                    f,
                    "custom section `{}`",
                    String::from_utf8_lossy(custom.name)
                )
            }
            TemporaryOutputSectionId::EhFrameData => write!(f, "eh_frame data"),
        }
    }
}
