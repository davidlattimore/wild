// Mach-O platform support for wild linker.
#![allow(unused_variables, dead_code)]

use crate::OutputKind;
use crate::args::macho::MachOArgs;
use crate::ensure;
use crate::error;
use crate::platform;
use crate::platform::SectionAttributes as _;
use object::Endianness;
use object::macho;
use object::read::macho::MachHeader;
use object::read::macho::Nlist;
use object::read::macho::Section as MachOSectionTrait;
use object::read::macho::Segment as MachOSegmentTrait;

#[derive(Debug, Copy, Clone)]
pub(crate) struct MachO;

const LE: Endianness = Endianness::Little;

type SectionTable<'data> = &'data [macho::Section64<Endianness>];
type SymbolTable<'data> = object::read::macho::SymbolTable<'data, macho::MachHeader64<Endianness>>;
pub(crate) type SymtabEntry = macho::Nlist64<Endianness>;

/// Wraps a Mach-O Section64 so we can implement platform traits on it.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub(crate) struct SectionHeader(pub(crate) macho::Section64<Endianness>);

/// Walks every input object and totals up the number of
/// `__eh_frame` FDEs plus the number of `__compact_unwind` entries
/// that will end up in the final `__unwind_info`. Used by
/// `apply_late_size_adjustments_epilogue` to size the trailing
/// `__unwind_info` slot in `__TEXT` before segment layout is
/// finalised — too small and wild would silently drop the section
/// (the pre-fix behaviour); too large and we'd waste a whole extra
/// page per binary.
///
/// **Complexity:** 𝒪(m · s · (f + u)) CPU where m = object files,
/// s = segments per object, f = FDE count in `__eh_frame`, u = entry
/// count in `__compact_unwind`. 𝒪(1) extra memory (running tally only).
pub(crate) fn estimate_unwind_info_entries(
    symbol_db: &crate::symbol_db::SymbolDb<'_, MachO>,
) -> usize {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;
    let le = object::Endianness::Little;
    let mut total = 0usize;
    for group in &symbol_db.groups {
        let crate::grouping::Group::Objects(objects) = group else {
            continue;
        };
        for seq in *objects {
            let data = seq.parsed.object.data;
            let Ok(header) = object::macho::MachHeader64::<object::Endianness>::parse(data, 0)
            else {
                continue;
            };
            let Ok(mut cmds) = header.load_commands(le, data, 0) else {
                continue;
            };
            while let Ok(Some(cmd)) = cmds.next() {
                let Ok(Some((seg, seg_data))) = cmd.segment_64() else {
                    continue;
                };
                let Ok(sections) = seg.sections(le, seg_data) else {
                    continue;
                };
                for sec in sections {
                    let segname = trim_nul(&sec.segname);
                    let sectname = trim_nul(&sec.sectname);
                    let sec_off = sec.offset.get(le) as usize;
                    let sec_size = sec.size.get(le) as usize;
                    if sec_size == 0 {
                        continue;
                    }
                    let Some(bytes) = data.get(sec_off..sec_off + sec_size) else {
                        continue;
                    };
                    if sectname == b"__eh_frame" {
                        // Walk the frame, counting FDEs (entries whose CIE
                        // pointer is non-zero).
                        let mut pos = 0usize;
                        while pos + 8 <= bytes.len() {
                            let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap())
                                as usize;
                            if len == 0 {
                                break;
                            }
                            let cie_ptr =
                                u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap());
                            if cie_ptr != 0 {
                                total += 1;
                            }
                            pos += 4 + len;
                        }
                    } else if segname == b"__LD" && sectname == b"__compact_unwind" {
                        // Each entry is 32 bytes; skip those with encoding == 0
                        // (leaf functions) and DWARF-mode (those come via
                        // FDE). Consistent with
                        // `collect_compact_unwind_entries`.
                        let n = sec_size / 32;
                        for i in 0..n {
                            let base = i * 32;
                            if base + 32 > bytes.len() {
                                break;
                            }
                            let encoding =
                                u32::from_le_bytes(bytes[base + 12..base + 16].try_into().unwrap());
                            if encoding == 0 {
                                continue;
                            }
                            if (encoding & 0x0F00_0000) == 0x0300_0000 {
                                continue; // DWARF — counted via FDE
                            }
                            total += 1;
                        }
                    }
                }
            }
        }
    }
    total
}

/// Upper-bound byte count of the `__unwind_info` section we'll emit,
/// rounded up to 4-byte alignment. Kept in sync with
/// `build_unwind_info_section` in `macho_writer.rs`:
///   header(28) + common_enc(4) + pers(n_pers*4)
///   + top_idx((pages+1)*12) + lsda(k*8)
///   + sl_pages(pages * (8 + per_page_entries*8))
/// Assumptions: 4 personalities, every entry has an LSDA descriptor
/// (8-byte pair), 500 entries per 2nd-level page. Overshoots but
/// never undershoots. Returns 0 when no unwind entries exist, so the
/// caller can skip the reservation entirely.
///
/// **Complexity:** Θ(m · s · (f + u)) CPU (delegates entirely to
/// `estimate_unwind_info_entries`); arithmetic on the result is 𝒪(1).
/// 𝒪(1) memory.
pub(crate) fn unwind_info_reserved_bytes(symbol_db: &crate::symbol_db::SymbolDb<'_, MachO>) -> u64 {
    let entries = estimate_unwind_info_entries(symbol_db);
    if entries == 0 {
        return 0;
    }
    const ENTRIES_PER_PAGE: usize = 500;
    let pages = entries.div_ceil(ENTRIES_PER_PAGE);
    let bytes = 28 + 4 + 4 * 4 + (pages + 1) * 12 + entries * 8 + pages * 8 + entries * 8;
    (bytes as u64 + 3) & !3
}

#[derive(derive_more::Debug)]
pub(crate) struct File<'data> {
    #[debug(skip)]
    pub(crate) data: &'data [u8],
    #[debug(skip)]
    pub(crate) sections: SectionTable<'data>,
    #[debug(skip)]
    pub(crate) symbols: SymbolTable<'data>,
    pub(crate) flags: u32,
}

/// Mach-O-specific per-object state carried alongside
/// `ObjectLayoutState`. Holds a lazily-built LSDA map derived from
/// the input object's `__compact_unwind`: each covered function's
/// byte offset in its `__text` maps to the `__gcc_except_tab`
/// byte offset of its LSDA. The atom-activation path in
/// `scan_atom_relocations` consults it so LSDA atoms ride along
/// with their function's liveness — ld64's
/// `kindNoneGroupSubordinateLSDA` direction without a DWARF
/// parser.
#[derive(Default, Debug)]
pub(crate) struct ObjectLayoutStateExt {
    pub(crate) lsda_map: std::sync::OnceLock<LsdaMap>,
    /// Set once this object's `__LD,__compact_unwind` section has
    /// been walked for personality-function GOT requests. The walk
    /// is part of `load_object_section_relocations`, which fires
    /// once per activated section in the object — without this
    /// flag, a typical object with N sections parses its full Mach-O
    /// load-command stream N times, contributing a quadratic factor
    /// to GC wall-clock on large inputs.
    pub(crate) compact_unwind_scanned: std::sync::atomic::AtomicBool,
}

/// Function offset → LSDA location, with section indices
/// identified by their 0-based `object::SectionIndex` form. The
/// key is the function's `(text_section_index, offset_within_text)`
/// as emitted by `__compact_unwind`'s non-extern function
/// relocation. Value is the same shape for `__gcc_except_tab`.
pub(crate) type LsdaMap = std::collections::HashMap<(u32, u64), (object::SectionIndex, u64)>;

impl<'data> File<'data> {
    /// Returns true when the object asserts `.subsections_via_symbols`
    /// (i.e. the `MH_SUBSECTIONS_VIA_SYMBOLS` bit is set in the Mach-O
    /// header). ld64 treats each non-local label in such a section as
    /// its own subsection — aligned to the containing section's
    /// alignment when emitted, and GC'able independently. Wild
    /// honours the alignment half today via
    /// [`compute_subsection_padding_deltas`]; per-subsection GC is a
    /// follow-up (see `subsections-via-symbols-plan.md`).
    pub(crate) fn has_subsections_via_symbols(&self) -> bool {
        self.flags & macho::MH_SUBSECTIONS_VIA_SYMBOLS != 0
    }
}

/// Enumerates atoms for one `__text` section under
/// `.subsections_via_symbols`. Returns an empty vec when the object
/// or section isn't flagged, and never splits data sections — ld64
/// only atomises pure-text the same way.
///
/// Invariants honoured:
/// * atoms are sorted by `input_start`;
/// * consecutive atoms are contiguous (`atom[i].input_end == atom[i+1].input_start`);
/// * the last atom's `input_end` equals the section's declared size;
/// * the first atom always starts at `0` regardless of whether a symbol is defined there — ld64
///   treats the head of the section as an atom anchored on the first-declared symbol (or an
///   anonymous one if none covers offset 0).
/// After atom GC completes, reclaim the bytes held by dormant atoms
/// in atom-managed sections (`__text`, `__const` in `__TEXT` and
/// `__DATA`, `__gcc_except_tab`) and the FDEs that don't survive the
/// per-atom filter in `__eh_frame`.
///
/// Two mechanisms, one entry point:
///
/// 1. `__eh_frame`: runs the same `is_fde_live` predicate as the writer, sums kept entries, shrinks
///    `section.size`.
/// 2. Atom-managed sections: walks `subsection_tracking`, accumulates `(input_start, +size)`
///    deletion deltas for unscanned atoms, merges them into `section_relax_deltas` (alongside any
///    existing padding insertions) and shrinks `section.size` by the total deletion. Symbol VMs
///    then flow through `opt_input_to_output` in `finalise_layout` so live atoms land at their
///    compacted offsets automatically.
///
/// **Complexity:** 𝒪(s · (r_eh + f) + a) CPU per object. The FDE
/// loop is now 𝒪(r_eh) to pre-bucket relocs by `r_address` + 𝒪(f)
/// HashMap lookups (one per FDE entry) — the old 𝒪(f · r_eh)
/// inner scan is gone. `s` = atom-managed sections, `f` = FDE count
/// in `__eh_frame`, `r_eh` = relocations in that section, `a` =
/// atoms across all atom-managed sections. The section-slot lookup
/// is 𝒪(1) via a prebuilt `slot_by_input_idx` map (was 𝒪(s)). The
/// debug-assertion path adds a second 𝒪(a · |Δ|) scan; production
/// is unaffected. 𝒪(s + a + r_eh) memory for the lookup map plus
/// `updates` / `deletions` vecs.
pub(crate) fn compact_atom_managed_sections<'data>(
    object: &mut crate::layout::ObjectLayoutState<'data, MachO>,
    common: &mut crate::layout::CommonGroupState<'data, MachO>,
    output_sections: &crate::output_section_id::OutputSections<'data, MachO>,
) {
    use crate::eh_frame::EhFrameEntryPrefix;
    use crate::resolution::SectionSlot;
    use object::read::macho::Nlist as _;
    use object::read::macho::Section as _;
    use std::mem::size_of;
    use zerocopy::FromBytes;
    const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();
    let le = LE;

    // Split the borrow: walk sections read-only to compute new
    // sizes, then apply them in a second pass.
    // Most objects have at most one __eh_frame section; a small pre-size
    // avoids the first realloc on the typical single-section case.
    let mut updates: Vec<(usize, u64)> = Vec::with_capacity(2);
    for (slot_idx, slot) in object.sections.iter().enumerate() {
        let SectionSlot::Loaded(section) = slot else {
            continue;
        };
        let Some(input_section) = object.object.sections.get(section.index.0) else {
            continue;
        };
        if trim_nul(input_section.sectname()) != b"__eh_frame" {
            continue;
        }
        let input_offset = input_section.offset(le) as usize;
        let input_size = input_section.size(le) as usize;
        if input_size == 0 || input_offset == 0 {
            continue;
        }
        let Some(input_data) = object
            .object
            .data
            .get(input_offset..input_offset + input_size)
        else {
            continue;
        };
        let Ok(relocs) = input_section.relocations(le, object.object.data) else {
            continue;
        };

        // Same liveness predicate as `write_filtered_eh_frame` uses
        // at write time. Keeping these in lockstep is critical —
        // if they disagree the layout-reserved bytes won't match
        // the writer's output.
        //
        // Pre-bucket `__eh_frame` relocs by `r_address` so the
        // per-FDE predicate is 𝒪(1) instead of 𝒪(r_eh). Each FDE
        // has at most one PC_BEGIN reloc at `entry_pos +
        // FDE_PC_BEGIN_OFFSET`; we look that exact offset up
        // directly. Same trick `build_lsda_map` already uses for
        // `__compact_unwind`.
        let sections_slice = object.sections.as_slice();
        let relocs_by_addr: std::collections::HashMap<u32, object::macho::RelocationInfo> = {
            let mut m = std::collections::HashMap::with_capacity(relocs.len());
            for reloc_raw in relocs {
                let ri = reloc_raw.info(le);
                // PC_BEGIN relocs are always the first at that byte;
                // `build_lsda_map` merges duplicates by priority, but
                // here only the extern=1, r_type=0 entry matters and
                // a single address can only carry one reloc anyway.
                m.insert(ri.r_address as u32, ri);
            }
            m
        };
        let is_fde_live = |input_pos: usize, _next_input: usize| -> bool {
            let pc_begin_addr = (input_pos + crate::eh_frame::FDE_PC_BEGIN_OFFSET) as u32;
            let Some(reloc) = relocs_by_addr.get(&pc_begin_addr) else {
                return false;
            };
            if !reloc.r_extern || reloc.r_type != 0 {
                return false;
            }
            let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
            let Ok(sym) = object.object.symbols.symbol(sym_idx) else {
                return false;
            };
            let n_sect = sym.n_sect();
            if n_sect == 0 {
                return false;
            }
            let tgt_sec_idx = n_sect as usize - 1;
            if let Some(tracking) = object.subsection_tracking.get(&tgt_sec_idx) {
                let Some(tgt_sec) = object.object.sections.get(tgt_sec_idx) else {
                    return false;
                };
                let sec_addr = tgt_sec.addr.get(le);
                let offset_in_sec = sym.n_value(le).wrapping_sub(sec_addr);
                if let Some(atom_idx) = tracking.atom_index_for_offset(offset_in_sec) {
                    return tracking.scanned[atom_idx];
                }
                false
            } else {
                matches!(
                    sections_slice.get(tgt_sec_idx),
                    Some(SectionSlot::Loaded(_))
                )
            }
        };

        // Walk entries; CIEs are always kept, FDEs iff their
        // target atom was scanned.
        let mut kept: u64 = 0;
        let mut pos = 0usize;
        while pos + PREFIX_LEN <= input_data.len() {
            let Ok(prefix) =
                EhFrameEntryPrefix::read_from_bytes(&input_data[pos..pos + PREFIX_LEN])
            else {
                break;
            };
            if prefix.length == 0 {
                break;
            }
            let entry_size = 4 + prefix.length as usize;
            let next = pos + entry_size;
            if next > input_data.len() {
                break;
            }
            let keep = prefix.cie_id == 0 || is_fde_live(pos, next);
            if keep {
                kept += entry_size as u64;
            }
            pos = next;
        }

        updates.push((slot_idx, kept));
    }

    for (slot_idx, kept) in updates {
        let SectionSlot::Loaded(section) = &mut object.sections[slot_idx] else {
            continue;
        };
        let old_capacity = section.capacity(output_sections);
        section.size = kept;
        let new_capacity = section.capacity(output_sections);
        if old_capacity > new_capacity {
            common.release(section.part_id, old_capacity - new_capacity);
        }
    }

    // Atom-managed sections: convert dormant atoms into deletion
    // deltas. `merge_additional` combines them with any existing
    // padding insertions, and the resulting sign-aware map drives
    // both the writer's compacted copy path (`copy_section_with_
    // subsection_padding` treats positive deltas as skips) and the
    // symbol-resolver's `input_to_output_offset` lookup (so live
    // atoms' VMs land at their compacted positions).
    //
    // Compact pure-text, `__const` (both `__TEXT` and `__DATA`),
    // and `__gcc_except_tab`. LSDA reverse-edge activation
    // (from `build_lsda_map`) drives which `__gcc_except_tab`
    // atoms stay live: a text atom's scan queues its LSDA atom
    // for activation through `push_section_activation`.
    //
    // Pure-text compaction relies on `section_local_vm` in
    // macho_writer (the three `sec_out + n_value - sec_in`
    // sites) routing local-temp-label resolution through
    // `section_relax_deltas.input_to_output_offset`, so
    // references to `ltmp*` / `L*` / `l*` labels from other
    // sections land on the compacted positions.
    let n_tracking = object.subsection_tracking.len();
    let mut section_indices: Vec<usize> = Vec::with_capacity(n_tracking);
    section_indices.extend(
        object
            .subsection_tracking
            .keys()
            .copied()
            .filter(|&sec_idx| {
                let Some(s) = object.object.sections.get(sec_idx) else {
                    return false;
                };
                let sectname = trim_nul(s.sectname());
                let is_pure_text = s.flags.get(LE) & macho::S_ATTR_PURE_INSTRUCTIONS != 0;
                sectname == b"__const" || sectname == b"__gcc_except_tab" || is_pure_text
            }),
    );
    // Build a single input_section_index → slot_idx lookup so the
    // per-section body below is 𝒪(1) instead of 𝒪(s) (was a full
    // `object.sections.iter().position(...)` per section — 𝒪(s²)
    // across the outer loop).
    let n_slots = object.sections.len();
    let slot_by_input_idx: std::collections::HashMap<usize, usize> = object
        .sections
        .iter()
        .enumerate()
        .filter_map(|(slot_idx, slot)| match slot {
            SectionSlot::Loaded(s) => Some((s.index.0, slot_idx)),
            _ => None,
        })
        .fold(
            std::collections::HashMap::with_capacity(n_slots),
            |mut m, (k, v)| {
                m.insert(k, v);
                m
            },
        );
    for sec_idx in section_indices {
        // Pull atoms/scanned out; we'll need to mutate
        // section_relax_deltas separately.
        let (deletions, total_deletion): (Vec<(u64, i32)>, u64) = {
            let Some(tracking) = object.subsection_tracking.get(&sec_idx) else {
                continue;
            };
            let mut out: Vec<(u64, i32)> = Vec::with_capacity(tracking.atoms.len());
            let mut total: u64 = 0;
            for (idx, atom) in tracking.atoms.iter().enumerate() {
                if tracking.scanned[idx] {
                    continue;
                }
                let size = atom.input_end.saturating_sub(atom.input_start);
                if size == 0 {
                    continue;
                }
                // `merge_additional` forbids duplicate offsets.
                // If an insertion delta already exists at the same
                // input_offset (e.g. alignment padding at the
                // start of this atom), we'd collide. For now,
                // skip the delta if an entry is already there —
                // the savings are smaller than the correctness
                // risk of stomping a padding insertion.
                if let Some(existing) = object.section_relax_deltas.get(sec_idx) {
                    if existing.has_delta_at(atom.input_start) {
                        continue;
                    }
                }
                out.push((atom.input_start, size as i32));
                total += size;
            }
            (out, total)
        };
        if deletions.is_empty() {
            continue;
        }

        // Update the section record to reflect the shrunken size
        // and release the reclaimed capacity.
        let Some(&slot_idx) = slot_by_input_idx.get(&sec_idx) else {
            continue;
        };
        let SectionSlot::Loaded(section) = &mut object.sections[slot_idx] else {
            continue;
        };
        let old_capacity = section.capacity(output_sections);
        section.size = section.size.saturating_sub(total_deletion);
        let new_capacity = section.capacity(output_sections);
        if old_capacity > new_capacity {
            common.release(section.part_id, old_capacity - new_capacity);
        }

        // Merge deletion deltas into the section's relax map.
        if let Some(existing) = object.section_relax_deltas.get_mut(sec_idx) {
            existing.merge_additional(deletions);
        } else {
            object.section_relax_deltas.insert_sorted(
                sec_idx,
                linker_utils::relaxation::SectionDeltas::new(deletions),
            );
        }

        // Invariant (debug-only): every deletion entry we just
        // added must match a dormant atom's
        // `[input_start..input_end)` exactly. If a delta doesn't
        // align to atom boundaries, `input_to_output_offset`
        // returns garbage for any symbol whose input offset falls
        // inside that unaligned range — a silent corruption that
        // only shows up at runtime. Checks the full delta map
        // after merge, so a delta we authored *and* a
        // pre-existing subsection-padding delta that happens to
        // land mid-atom both get caught.
        #[cfg(debug_assertions)]
        if let Some(tracking) = object.subsection_tracking.get(&sec_idx) {
            if let Some(deltas) = object.section_relax_deltas.get(sec_idx) {
                for d in deltas.deltas() {
                    if d.bytes_delta <= 0 {
                        continue; // insertion (padding); not an atom delete
                    }
                    let lo = d.input_offset;
                    let hi = lo + d.bytes_delta as u64;
                    let matches_atom = tracking.atoms.iter().enumerate().any(|(i, atom)| {
                        atom.input_start == lo && atom.input_end == hi && !tracking.scanned[i]
                    });
                    debug_assert!(
                        matches_atom,
                        "compact_atom_managed_sections: deletion delta \
                         [{lo:#x}..{hi:#x}) in sec_idx={sec_idx} does not \
                         match any dormant atom's input range — \
                         input_to_output_offset will corrupt VMs of live \
                         symbols whose offsets fall in this range"
                    );
                }
            }
        }
    }

    // Diagnostic trace: atom activation stats per __gcc_except_tab
    // so we can see whether the ld64 gap comes from activation
    // eagerness or from something else. Gate on WILD_LSDA_STATS.
    if std::env::var("WILD_LSDA_STATS").is_ok() {
        use object::read::macho::Section as _;
        for (sec_idx, tracking) in &object.subsection_tracking {
            let Some(s) = object.object.sections.get(*sec_idx) else {
                continue;
            };
            if trim_nul(s.sectname()) != b"__gcc_except_tab" {
                continue;
            }
            let total = tracking.atoms.len();
            let active = tracking.scanned.iter().filter(|b| **b).count();
            eprintln!(
                "wild-lsda-stats: {} gcc_except_tab atoms active={active}/{total}",
                object.input.file.filename.display()
            );
        }
    }

    // Invariant (debug-only): LSDA reverse-edge completeness.
    // For every (fn_atom, lsda_atom) pair the LSDA map knows
    // about, if the fn atom is live, the LSDA atom must be too
    // — otherwise a live FDE at write time will reference a
    // dormant LSDA whose bytes got deleted, and the runtime
    // unwinder reads garbage (SIGSEGV on panic). Catches the
    // same failure class we hit on rust-panic-unwind before the
    // build_lsda_map was extended to cover DWARF-mode FDEs.
    #[cfg(debug_assertions)]
    {
        let map = build_lsda_map(object.object);
        for (&(fn_sec_u32, fn_off), &(lsda_sec, lsda_off)) in &map {
            let fn_sec = fn_sec_u32 as usize;
            let Some(fn_tracking) = object.subsection_tracking.get(&fn_sec) else {
                continue;
            };
            let Some(fn_atom_idx) = fn_tracking.atom_index_for_offset(fn_off) else {
                continue;
            };
            if !fn_tracking.scanned[fn_atom_idx] {
                continue; // fn not live → FDE dropped; LSDA can be dormant
            }
            // fn atom is live. Ensure LSDA atom is also live.
            let Some(lsda_tracking) = object.subsection_tracking.get(&lsda_sec.0) else {
                // LSDA's section isn't atom-managed — no dormancy check possible.
                continue;
            };
            let Some(lsda_atom_idx) = lsda_tracking.atom_index_for_offset(lsda_off) else {
                debug_assert!(
                    false,
                    "LSDA reverse-edge invariant: fn at sec {fn_sec}+{fn_off:#x} \
                     references LSDA at sec {lsda_sec_idx}+{lsda_off:#x} but \
                     the LSDA offset doesn't map to any atom",
                    lsda_sec_idx = lsda_sec.0
                );
                continue;
            };
            debug_assert!(
                lsda_tracking.scanned[lsda_atom_idx],
                "LSDA reverse-edge invariant: fn at sec {fn_sec}+{fn_off:#x} \
                 is live (atom #{fn_atom_idx}) but its LSDA at sec \
                 {lsda_sec_idx}+{lsda_off:#x} (atom #{lsda_atom_idx}) is \
                 dormant — activation miss. Extending `build_lsda_map` or \
                 scan_reloc_range_for_atom_impl's LSDA push is the fix.",
                lsda_sec_idx = lsda_sec.0
            );
        }
    }
}

/// Partitions one input section into subsection atoms under
/// `.subsections_via_symbols`. Returns an empty vec for non-text /
/// non-const / non-gcc_except_tab sections, or when the file flag is
/// absent.
///
/// **Complexity:** Θ(n_sym + a·log a) CPU where n_sym = total symbol
/// count in the object (linear scan to filter to this section) and a
/// = anchoring symbols in this section (sort + dedup of `boundaries`).
/// Output vec is 𝒪(a) entries. 𝒪(a) memory.
pub(crate) fn compute_atoms(
    file: &File<'_>,
    section_index: object::SectionIndex,
) -> Vec<crate::layout::Atom> {
    if !file.has_subsections_via_symbols() {
        return Vec::new();
    }
    let Some(section) = file.sections.get(section_index.0) else {
        return Vec::new();
    };
    let section_size = section.size.get(LE);
    if section_size == 0 {
        return Vec::new();
    }
    // Atomise pure-text unconditionally, plus relocation-bearing
    // data sections that are pure read-only-const candidates.
    // Sections whose atoms are live for reasons other than text
    // relocation reachability (runtime-invoked init/term lists,
    // mutable state, TLS descriptors the TLV machinery re-keys by
    // offset) must stay whole-section: their atoms can't be
    // zero-filled when dormant without breaking the runtime
    // semantics wild already handles elsewhere.
    //
    // Today this is limited to `__const` in either `__TEXT` or
    // `__DATA`. That's where rust's and clang's function-pointer
    // tables live and where the import-bloat dominates. Widening
    // to `__data` / `__thread_*` would need additional careful
    // audit — see `project_macho_crash.md` for the TLV-offset
    // validator fire and unwind-info GOT underflow we saw when
    // atomising TLS descriptors.
    let flags = section.flags.get(LE);
    let is_pure_text = flags & macho::S_ATTR_PURE_INSTRUCTIONS != 0;
    let sectname = trim_nul(section.sectname());
    // Atomise any `__const` section — regardless of whether it
    // carries its own relocs. rustc's `__TEXT,__const` holds pure
    // literal tables (no outgoing relocs) but its 471+ `l_anon.*`
    // symbols DO anchor separately referenced atoms; without
    // atomisation the whole section rides one coarse live tag
    // and dead literals ship. The reloc-bearing check was an
    // early guard written before per-atom activation worked the
    // way it does now (activation comes from incoming refs, not
    // outgoing ones).
    let is_const_data = !is_pure_text && sectname == b"__const";
    // `__gcc_except_tab` holds LSDA records (anchored at
    // `GCC_except_tableN` symbols). Atomising it lets the
    // reverse-edges path — function → LSDA via `__compact_unwind`
    // — activate exactly the LSDA belonging to each live
    // function, while leaving unreached LSDAs dormant. See
    // `build_lsda_map` and the scan-loop hook in
    // `scan_reloc_range_for_atom_impl`.
    // `__gcc_except_tab` has no outgoing relocs in rustc output
    // (call-site/action tables are function-relative offsets).
    // The old `nreloc != 0` guard suppressed atomisation for
    // every rust object. Incoming activation (from text atoms'
    // reverse-edge via `build_lsda_map`) works regardless of
    // whether this section carries its own relocs — same logic
    // that unblocked `__TEXT,__const` atomisation.
    let is_gcc_except_tab = !is_pure_text && sectname == b"__gcc_except_tab";
    if !is_pure_text && !is_const_data && !is_gcc_except_tab {
        return Vec::new();
    }
    let is_text_for_anchor_rule = is_pure_text;

    let section_addr = section.addr.get(LE);
    let sect_num_1based = section_index.0 as u8 + 1;

    // Collect (offset, symbol_index) for N_SECT symbols anchoring
    // atoms. ld64's rule for `.subsections_via_symbols` is "divide at
    // each non-local label" — that's any non-stab N_SECT symbol
    // whose assembler-scope name isn't private-local (`L*` / `l*`).
    // Private externs (N_PEXT) and file-scoped non-private symbols
    // both anchor atoms; pure-extern-only was the previous filter
    // and it left atoms too coarse (one per global function) which
    // underprunes in Rust's CGUs where many anchor points are
    // N_PEXT or file-scoped compiler-generated functions.
    // Typical Rust CGU: a few dozen symbols per section. Pre-allocate
    // generously enough to avoid early realloc without overshooting.
    let mut boundaries: Vec<(u64, object::SymbolIndex)> = Vec::with_capacity(16);
    for (idx, sym) in file.symbols.iter().enumerate() {
        let n_type = sym.n_type();
        if n_type & macho::N_STAB != 0 {
            continue;
        }
        if n_type & macho::N_TYPE != macho::N_SECT {
            continue;
        }
        if sym.n_sect() != sect_num_1based {
            continue;
        }
        let name = match sym.name(LE, file.symbols.strings()) {
            Ok(n) => n,
            Err(_) => continue,
        };
        // In `__TEXT` sections the `L*` / `l*` prefix marks a
        // scratch label (jump target, stringpool offset) that does
        // not anchor a subsection atom. In data sections the same
        // prefix IS the atomiser — rust's `l_anon.*` entries in
        // `__DATA,__const` are the primary function-pointer-table
        // boundaries, and without them we'd see one atom spanning
        // the whole section, defeating the GC. Apply the filter
        // text-only.
        if is_text_for_anchor_rule && is_private_local_label(name) {
            continue;
        }
        let offset = sym.n_value(LE).wrapping_sub(section_addr);
        if offset >= section_size {
            continue;
        }
        boundaries.push((offset, object::SymbolIndex(idx)));
    }
    boundaries.sort_by_key(|(o, _)| *o);
    boundaries.dedup_by_key(|(o, _)| *o);
    if boundaries.is_empty() {
        return Vec::new();
    }

    // Synthesise a leading atom if the first symbol isn't at offset 0
    // (the head-of-section bytes still exist and ld64 keeps them
    // grouped with whatever the assembler emits first). Anchor is
    // the first external symbol — a later refinement could track
    // "anchorless" atoms separately, but for GC purposes they ride
    // along with the first real symbol's liveness.
    let mut atoms: Vec<crate::layout::Atom> = Vec::with_capacity(boundaries.len() + 1);
    if boundaries[0].0 > 0 {
        atoms.push(crate::layout::Atom {
            input_start: 0,
            input_end: boundaries[0].0,
            anchor: boundaries[0].1,
        });
    }
    for i in 0..boundaries.len() {
        let (start, anchor) = boundaries[i];
        let end = boundaries
            .get(i + 1)
            .map(|(next_off, _)| *next_off)
            .unwrap_or(section_size);
        if end <= start {
            continue;
        }
        atoms.push(crate::layout::Atom {
            input_start: start,
            input_end: end,
            anchor,
        });
    }
    atoms
}

/// Builds the `function → LSDA` map from an input object's
/// `__compact_unwind` section. One entry per compact-unwind
/// record whose function and LSDA relocations resolve to
/// non-extern targets (i.e. same-object section offsets).
/// Entries with only a function relocation (no LSDA — function
/// has no C++-style cleanup) or with extern LSDA refs (rare) are
/// skipped.
///
/// `__compact_unwind` entries are 32 bytes each:
/// ```text
/// 0..8   function address     (non-extern reloc to __text)
/// 8..12  length
/// 12..16 compact encoding
/// 16..24 personality pointer  (extern reloc to personality fn)
/// 24..32 LSDA pointer         (non-extern reloc to __gcc_except_tab)
/// ```
///
/// **Complexity:** Θ(lsda + f) CPU where lsda = `__compact_unwind`
/// entries and f = FDE entries in `__eh_frame` (two separate linear
/// passes). Building `relocs_by_off` is 𝒪(r) per section. Total is
/// Θ(r + lsda + f). 𝒪(r + lsda + f) memory for the reloc hash map
/// and result `LsdaMap`.
pub(crate) fn build_lsda_map(file: &File<'_>) -> LsdaMap {
    use object::read::macho::MachHeader as _;
    use object::read::macho::Nlist as _;
    use object::read::macho::Section as _;
    use object::read::macho::Segment as _;

    let n_secs = file.sections.len();
    // Rough upper bound: one LSDA per function; real Rust CGUs average ~2-4
    // functions per object with LSDAs. Avoid zero-capacity start.
    let mut map = LsdaMap::with_capacity(n_secs.max(4));
    let le = LE;
    let data = file.data;

    // `__gcc_except_tab` section indices — used to identify the
    // target of an `__eh_frame` FDE's LSDA reloc when we scan
    // DWARF-mode entries below.
    let except_tab_secs: std::collections::HashSet<usize> = (0..n_secs)
        .filter(|&i| {
            file.sections
                .get(i)
                .map(|s| trim_nul(s.sectname()) == b"__gcc_except_tab")
                .unwrap_or(false)
        })
        .fold(std::collections::HashSet::with_capacity(2), |mut s, i| {
            s.insert(i);
            s
        });

    let Ok(header) = macho::MachHeader64::<Endianness>::parse(data, 0) else {
        return map;
    };
    let Ok(mut cmds) = header.load_commands(le, data, 0) else {
        return map;
    };

    while let Ok(Some(cmd)) = cmds.next() {
        let Ok(Some((seg, seg_data))) = cmd.segment_64() else {
            continue;
        };
        let Ok(sections) = seg.sections(le, seg_data) else {
            continue;
        };
        for sec in sections {
            let segname = trim_nul(&sec.segname);
            let sectname = trim_nul(&sec.sectname);
            let is_compact_unwind = segname == b"__LD" && sectname == b"__compact_unwind";
            let is_eh_frame = segname == b"__TEXT" && sectname == b"__eh_frame";
            if !is_compact_unwind && !is_eh_frame {
                continue;
            }
            let Ok(relocs) = sec.relocations(le, data) else {
                continue;
            };

            // Bucket relocs by r_address so we can look up the
            // per-entry function reloc (@0) and LSDA reloc (@24)
            // without a linear scan per entry.
            let mut relocs_by_off: std::collections::HashMap<u32, object::macho::RelocationInfo> =
                std::collections::HashMap::with_capacity(relocs.len());
            for r in relocs {
                let ri = r.info(le);
                // For SUBTRACTOR+UNSIGNED pairs at the same
                // r_address, the UNSIGNED half names the real
                // target — keep that one.
                let addr = ri.r_address as u32;
                match relocs_by_off.get(&addr) {
                    Some(existing) if existing.r_type == 1 => {
                        relocs_by_off.insert(addr, ri);
                    }
                    Some(_) => {}
                    None => {
                        relocs_by_off.insert(addr, ri);
                    }
                }
            }

            let sec_file_off = sec.offset.get(le) as usize;
            let sec_size = sec.size.get(le) as usize;
            let Some(sec_bytes) =
                data.get(sec_file_off..sec_file_off.checked_add(sec_size).unwrap_or(0))
            else {
                continue;
            };

            if is_compact_unwind {
                let n_entries = sec_size / 32;
                for i in 0..n_entries {
                    let entry_base = (i as u32) * 32;
                    let entry_off = (i * 32) as usize;

                    let Some(fn_reloc) = relocs_by_off.get(&entry_base) else {
                        continue;
                    };
                    let Some(fn_tgt) =
                        decode_non_extern_section_offset(file, sec_bytes, fn_reloc, entry_off)
                    else {
                        continue;
                    };

                    let Some(lsda_reloc) = relocs_by_off.get(&(entry_base + 24)) else {
                        continue;
                    };
                    let Some(lsda_tgt) = decode_non_extern_section_offset(
                        file,
                        sec_bytes,
                        lsda_reloc,
                        entry_off + 24,
                    ) else {
                        continue;
                    };

                    map.insert((fn_tgt.0.0 as u32, fn_tgt.1), lsda_tgt);
                }
            } else if is_eh_frame {
                // DWARF-mode FDEs encode the `(function, LSDA)`
                // relationship without the `__compact_unwind`
                // helper table. For each FDE in `__eh_frame`:
                //   - the `pc_begin` reloc at offset 8 names the target function (UNSIGNED half of
                //     the SUBTRACTOR+UNSIGNED pair, r_extern=1).
                //   - any reloc further inside the FDE whose target is a `__gcc_except_tab` section
                //     is the LSDA pointer.
                // Without this pass, the per-atom FDE filter in
                // `write_filtered_eh_frame` would keep such FDEs
                // but their LSDA atoms would stay dormant,
                // tripping `validate_eh_frame_consistency`.
                use crate::eh_frame::EhFrameEntryPrefix;
                use std::mem::size_of;
                use zerocopy::FromBytes;
                const PREFIX_LEN: usize = size_of::<EhFrameEntryPrefix>();

                let mut pos = 0usize;
                while pos + PREFIX_LEN <= sec_bytes.len() {
                    let Ok(prefix) =
                        EhFrameEntryPrefix::read_from_bytes(&sec_bytes[pos..pos + PREFIX_LEN])
                    else {
                        break;
                    };
                    if prefix.length == 0 {
                        break;
                    }
                    let entry_size = 4 + prefix.length as usize;
                    let next = pos.checked_add(entry_size).unwrap_or(sec_bytes.len() + 1);
                    if next > sec_bytes.len() {
                        break;
                    }

                    if prefix.cie_id != 0 {
                        // pc_begin target — UNSIGNED reloc at
                        // FDE offset 8.
                        let pc_addr = (pos + 8) as u32;
                        let fn_tgt = relocs_by_off.get(&pc_addr).and_then(|ri| {
                            if !ri.r_extern || ri.r_type != 0 {
                                return None;
                            }
                            let sym_idx = object::SymbolIndex(ri.r_symbolnum as usize);
                            let sym = file.symbols.symbol(sym_idx).ok()?;
                            let n_sect = sym.n_sect();
                            if n_sect == 0 {
                                return None;
                            }
                            let sec_idx = n_sect as usize - 1;
                            let tgt_sec = file.sections.get(sec_idx)?;
                            let tgt_addr = tgt_sec.addr.get(le);
                            let off = sym.n_value(le).checked_sub(tgt_addr)?;
                            Some((object::SectionIndex(sec_idx), off))
                        });

                        // LSDA target — any reloc inside this
                        // FDE whose target lands in
                        // `__gcc_except_tab`. Extern refs point
                        // to a `GCC_except_tableN` symbol;
                        // non-extern refs encode the target VM
                        // inline at the reloc address.
                        let mut lsda_tgt: Option<(object::SectionIndex, u64)> = None;
                        for r_addr in (pos as u32 + 8)..(next as u32) {
                            let Some(ri) = relocs_by_off.get(&r_addr) else {
                                continue;
                            };
                            // Skip the pc_begin reloc itself.
                            if r_addr == pc_addr {
                                continue;
                            }
                            if ri.r_extern {
                                let sym_idx = object::SymbolIndex(ri.r_symbolnum as usize);
                                let Ok(sym) = file.symbols.symbol(sym_idx) else {
                                    continue;
                                };
                                let n_sect = sym.n_sect();
                                if n_sect == 0 {
                                    continue;
                                }
                                let sec_idx = n_sect as usize - 1;
                                if !except_tab_secs.contains(&sec_idx) {
                                    continue;
                                }
                                let Some(tgt_sec) = file.sections.get(sec_idx) else {
                                    continue;
                                };
                                let tgt_addr = tgt_sec.addr.get(le);
                                if let Some(off) = sym.n_value(le).checked_sub(tgt_addr) {
                                    lsda_tgt = Some((object::SectionIndex(sec_idx), off));
                                    break;
                                }
                            } else {
                                let sec_num = ri.r_symbolnum as usize;
                                if sec_num == 0 || sec_num > file.sections.len() {
                                    continue;
                                }
                                if !except_tab_secs.contains(&(sec_num - 1)) {
                                    continue;
                                }
                                if let Some(tgt) = decode_non_extern_section_offset(
                                    file,
                                    sec_bytes,
                                    ri,
                                    r_addr as usize,
                                ) {
                                    lsda_tgt = Some(tgt);
                                    break;
                                }
                            }
                        }

                        if let (Some(fn_t), Some(lsda_t)) = (fn_tgt, lsda_tgt) {
                            map.entry((fn_t.0.0 as u32, fn_t.1)).or_insert(lsda_t);
                        }
                    }

                    pos = next;
                }
            }
        }
    }
    map
}

/// Decodes a non-extern relocation at position `pos` within
/// `sec_data` into `(target_section_index, target_byte_offset)`.
/// The 8-byte inline value at `pos` is treated as a target VM
/// address; we subtract the target section's own `addr` to get an
/// offset. Extern relocs, empty, or out-of-range targets return
/// `None`.
///
/// **Complexity:** 𝒪(1) CPU and memory — single array-index lookup
/// plus arithmetic on fixed-width integers.
fn decode_non_extern_section_offset(
    file: &File<'_>,
    sec_data: &[u8],
    reloc: &object::macho::RelocationInfo,
    pos: usize,
) -> Option<(object::SectionIndex, u64)> {
    if reloc.r_extern {
        return None;
    }
    let sec_num = reloc.r_symbolnum as usize;
    if sec_num == 0 || sec_num > file.sections.len() {
        return None;
    }
    let tgt_sec = file.sections.get(sec_num - 1)?;
    let tgt_addr = tgt_sec.addr.get(LE);
    let tgt_size = tgt_sec.size.get(LE);
    let end = pos.checked_add(8)?;
    if end > sec_data.len() {
        return None;
    }
    let val = u64::from_le_bytes(sec_data[pos..end].try_into().ok()?);
    if val < tgt_addr {
        return None;
    }
    let off = val - tgt_addr;
    if off >= tgt_size {
        return None;
    }
    Some((object::SectionIndex(sec_num - 1), off))
}

/// Mach-O "private label" predicate: labels whose name starts with
/// uppercase `L` or lowercase `l` are file-private in Apple's
/// assembler convention (they're stripped from the output symtab by
/// ld64's default `-X`). These do NOT anchor subsection atoms even
/// when `.subsections_via_symbols` is set — they're scratch labels
/// (jump targets, string-pool offsets, compiler-emitted anchors).
pub(crate) fn is_private_local_label(name: &[u8]) -> bool {
    matches!(name.first().copied(), Some(b'L') | Some(b'l'))
}

/// Decodes the target page of a non-extern `ARM64_RELOC_PAGE21`
/// relocation and returns it alongside the target section index
/// and the reloc's `r_symbolnum`, for pair-tracking with the
/// companion PAGEOFF12 inside [`scan_reloc_range_for_atom`].
///
/// Returns `None` when the reloc isn't non-extern PAGE21, when the
/// target section index is out of range, or when the ADRP bytes
/// can't be decoded (shouldn't happen on well-formed input).
///
/// **Complexity:** 𝒪(1) CPU and memory — one bounds check, a 4-byte
/// read, and a call to `decode_adrp_target_page` (also 𝒪(1)).
pub(crate) fn decode_pending_page21(
    file: &File<'_>,
    source_section: &macho::Section64<Endianness>,
    reloc: &object::macho::RelocationInfo,
) -> Option<(object::SectionIndex, u64, u32)> {
    if reloc.r_extern || reloc.r_type != 3 {
        return None;
    }
    let sec_num = reloc.r_symbolnum as usize;
    if sec_num == 0 || sec_num > file.sections.len() {
        return None;
    }
    let src_file_off = source_section.offset.get(LE) as usize;
    let src_size = source_section.size.get(LE) as usize;
    let src_data = file
        .data
        .get(src_file_off..src_file_off.checked_add(src_size)?)?;
    let r_addr_in_src = reloc.r_address as usize;
    let end = r_addr_in_src.checked_add(4)?;
    if end > src_data.len() {
        return None;
    }
    let insn = u32::from_le_bytes(src_data[r_addr_in_src..end].try_into().ok()?);
    let pc = source_section
        .addr
        .get(LE)
        .wrapping_add(reloc.r_address as u64);
    let target_page = decode_adrp_target_page(insn, pc)?;
    Some((
        object::SectionIndex(sec_num - 1),
        target_page,
        reloc.r_symbolnum,
    ))
}

/// Decodes the low 12 bits of a non-extern `ARM64_RELOC_PAGEOFF12`
/// relocation's target, from the instruction bytes at the reloc
/// source. Returns `None` when the reloc is not PAGEOFF12 or when
/// the instruction isn't a recognised LDR/STR/ADD imm-12 variant.
///
/// **Complexity:** 𝒪(1) CPU and memory — bounds check plus a call to
/// `decode_pageoff12_byte_offset` (pure bitwise, also 𝒪(1)).
pub(crate) fn decode_pageoff12_reloc(
    file: &File<'_>,
    source_section: &macho::Section64<Endianness>,
    reloc: &object::macho::RelocationInfo,
) -> Option<u32> {
    if reloc.r_extern || reloc.r_type != 4 {
        return None;
    }
    let src_file_off = source_section.offset.get(LE) as usize;
    let src_size = source_section.size.get(LE) as usize;
    let src_data = file
        .data
        .get(src_file_off..src_file_off.checked_add(src_size)?)?;
    let r_addr_in_src = reloc.r_address as usize;
    let end = r_addr_in_src.checked_add(4)?;
    if end > src_data.len() {
        return None;
    }
    let insn = u32::from_le_bytes(src_data[r_addr_in_src..end].try_into().ok()?);
    decode_pageoff12_byte_offset(insn)
}

/// Decodes an ARM64 `LDR (immediate, unsigned offset)` or
/// `ADD (immediate)` instruction word into the byte-offset-within-
/// page that Mach-O's `ARM64_RELOC_PAGEOFF12` patches.
///
/// Returns `None` if `insn` is neither a recognised LDR immediate
/// nor an ADD immediate — callers (the PAGE21/PAGEOFF12 pair
/// handling in [`decode_non_extern_target`]) treat that as
/// "decode failed, fall back to page-only activation".
///
/// Scaling: LDR's 12-bit immediate is scaled by the load size
/// (byte / halfword / word / doubleword). ADD's 12-bit immediate
/// is raw bytes. The returned value is always in raw bytes so
/// callers can add it to an ADRP-derived page to get the full
/// target VM address.
///
/// Encoding references (ARM ARM v8a):
/// * `LDR (immediate, unsigned offset)` — bits 31..30 = `size`, 27..26 = 11, 25..24 = 01, 23..22 =
///   opc (01 for load), 21..10 = imm12, 9..5 = Rn, 4..0 = Rt. Byte offset = imm12 << size.
/// * `ADD (immediate)` — bit 31 = sf, bits 30..24 = 0100010, 23..22 = shift (must be 00 for the
///   PAGEOFF12 case — shift-12 ADDs target things outside 4KB pages and aren't used for relocatable
///   text→data). Byte offset = imm12.
pub(crate) fn decode_pageoff12_byte_offset(insn: u32) -> Option<u32> {
    // `Load/store register (unsigned immediate)`, integer form —
    // bits 29..27 = 111 (class prefix), bit 26 = 0 (V=0 for
    // integer, 1 for FP/SIMD — the latter is rare for reloc use
    // and we skip it), bits 25..24 = 01 (unsigned-offset subclass).
    // Combined, bits 29..24 = 111001 = 0x39. `size` lives at bits
    // 31..30 and scales imm12 by `1 << size`.
    if (insn >> 24) & 0x3F == 0x39 {
        let size = (insn >> 30) & 0x3;
        let imm12 = (insn >> 10) & 0xFFF;
        return Some(imm12 << size);
    }

    // `ADD (immediate)` — bits 30..24 = 0b0010001 (sf is bit 31,
    // op/S = 00, fixed prefix 10001). Shift field bits 23..22 must
    // be `00`: the `01` variant left-shifts imm12 by 12 and
    // targets entire pages, which Mach-O never emits for a
    // PAGEOFF12 reloc.
    if (insn >> 24) & 0x7F == 0b0010001 && (insn >> 22) & 0x3 == 0 {
        let imm12 = (insn >> 10) & 0xFFF;
        return Some(imm12);
    }

    None
}

/// Decodes an ARM64 `ADRP` instruction word into the target page VM
/// address, given the PC at which the instruction executes.
///
/// Returns `None` if `insn` is not a valid `ADRP` encoding
/// (specifically: `op != 1` or the fixed opcode bits 24–28 don't
/// read `10000`). `ADR` (the non-page-shifted variant with `op=0`)
/// also returns `None` — callers that want to handle it can add a
/// separate case, but text→data references in relocatable objects
/// are always `ADRP`+offset pairs.
///
/// Encoding (ARM ARM v8a):
/// ```text
/// bit:  31 | 30 29 | 28 27 26 25 24 | 23 ........... 5 | 4 ... 0
///        1 | immlo | 1  0  0  0  0  | immhi            | Rd
/// ```
///
/// Target page = `(PC & !0xFFF) + sign_extend(imm21) << 12`
/// where `imm21 = (immhi << 2) | immlo`. The result is therefore
/// always 4KB-aligned.
///
/// This helper is unit-tested below against synthetic encodings;
/// the full decoder for non-extern Mach-O relocations in
/// [`decode_non_extern_target`] calls through here when it sees
/// `r_type == 3` (`ARM64_RELOC_PAGE21`).
pub(crate) fn decode_adrp_target_page(insn: u32, pc: u64) -> Option<u64> {
    // Bit 31 = 1 for ADRP, bits 28..24 = 0b10000, both required.
    if (insn >> 31) & 1 != 1 {
        return None;
    }
    if (insn >> 24) & 0x1f != 0x10 {
        return None;
    }
    let immlo = ((insn >> 29) & 0x3) as u64;
    let immhi = ((insn >> 5) & 0x7_FFFF) as u64;
    let imm21 = (immhi << 2) | immlo;
    // Sign-extend from 21 bits. Bit 20 of imm21 is the sign bit.
    let imm21_signed = if imm21 & (1 << 20) != 0 {
        (imm21 as i64) | !((1i64 << 21) - 1)
    } else {
        imm21 as i64
    };
    // imm21 counts pages (each 4 KiB); shift by 12 for bytes.
    let page_delta = imm21_signed.wrapping_shl(12);
    let source_page = pc & !0xFFF;
    Some((source_page as i64).wrapping_add(page_delta) as u64)
}

/// For a non-extern Mach-O relocation, decode the `(section,
/// byte_offset)` the reloc resolves to by reading the relocation
/// source's own bytes (which the assembler pre-populated with the
/// target VM address, encoded per the reloc type). Returns `None`
/// for reloc types we don't yet decode, malformed section bounds,
/// or when the computed offset lands outside the target section.
///
/// Reloc types handled (arm64):
///
/// * `r_type == 0, r_length == 3` — UNSIGNED, 8-byte absolute address inline in the source. Common
///   for function-pointer tables in `__DATA,__const`. Target VM is the literal 64-bit value at
///   `r_address`; byte offset = target_vm − section.addr.
/// * `r_type == 3` — PAGE21 (ADRP): target page encoded in the ADRP instruction's 21-bit signed
///   immediate (`immhi:immlo`). We recover the target page only; the companion PAGEOFF12 reloc
///   carries the low 12 bits. For atom activation we conservatively treat the page-start as the
///   triggering offset — as long as atoms don't span page boundaries (typical for rust / clang
///   data), this lands in the right atom.
/// * `r_type == 4` — PAGEOFF12 (LDR/ADD/STR immediate): ignored here. The PAGE21 that precedes it
///   already pushed an activation request; a separate one from PAGEOFF12 would just duplicate work.
/// * `r_type == 10` (ADDEND) — skipped.
///
/// Other types (SUBTRACTOR/PAIR, TLVP, branches) don't produce
/// text→data reachability and are skipped silently.
///
/// **Complexity:** 𝒪(1) CPU and memory — one match arm dispatch,
/// a single 8-byte slice read for UNSIGNED, or an early return for
/// all other types.
pub(crate) fn decode_non_extern_target(
    file: &File<'_>,
    source_section: &macho::Section64<Endianness>,
    reloc: &object::macho::RelocationInfo,
) -> Option<(object::SectionIndex, u64)> {
    if reloc.r_extern {
        return None;
    }
    let sec_num = reloc.r_symbolnum as usize;
    if sec_num == 0 || sec_num > file.sections.len() {
        return None;
    }
    let target_sec_idx = object::SectionIndex(sec_num - 1);
    let target_sec = file.sections.get(sec_num - 1)?;
    let target_addr = target_sec.addr.get(LE);
    let target_size = target_sec.size.get(LE);

    // Slice the source section's file-resident bytes to read the
    // relocation's source word.
    let src_file_off = source_section.offset.get(LE) as usize;
    let src_size = source_section.size.get(LE) as usize;
    let src_data = file
        .data
        .get(src_file_off..src_file_off.checked_add(src_size)?)?;
    let r_addr_in_src = reloc.r_address as usize;

    // Single-reloc target decoder: only `UNSIGNED` (8-byte inline
    // pointer) carries the full target VM address on its own. PAGE21
    // without a companion PAGEOFF12 is ambiguous about the low 12
    // bits, so pair-tracking of PAGE21+PAGEOFF12 happens in the
    // scan loop rather than here.
    let target_vm = match (reloc.r_type, reloc.r_length) {
        (0, 3) => {
            let end = r_addr_in_src.checked_add(8)?;
            if end > src_data.len() {
                return None;
            }
            u64::from_le_bytes(src_data[r_addr_in_src..end].try_into().ok()?)
        }
        _ => return None,
    };

    if target_vm < target_addr {
        return None;
    }
    let target_offset = target_vm - target_addr;
    if target_offset >= target_size {
        return None;
    }
    Some((target_sec_idx, target_offset))
}

/// Scans the subset of an input section's relocations whose
/// `r_address` falls within the given input-byte range, driving
/// symbol requests for each extern reference. Used by Mach-O's
/// per-atom GC (called once per atom activation) and by the default
/// whole-section scan (called with `0..u64::MAX` for non-
/// subsection-managed sections).
///
/// Semantics: a reloc at `r_address = X` is *inside* the atom if
/// `range.start <= X < range.end`. Relocs outside the range (or
/// meta relocs like ADDEND / SUBTRACTOR) are skipped. The
/// SUBTRACTOR→UNSIGNED pairing that ld64 uses for personality
/// pointers in `__eh_frame` CIEs is respected — the `after_subtractor`
/// state is local to this call and only triggers when both halves
/// fall inside the range.
///
/// **Complexity:** delegates entirely to `scan_reloc_range_for_atom_impl`
/// — see that function for the precise bound.
pub(crate) fn scan_reloc_range_for_atom<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    state: &crate::layout::ObjectLayoutState<'data, MachO>,
    queue: &mut crate::layout::LocalWorkQueue,
    resources: &'scope crate::layout::GraphResources<'data, '_, MachO>,
    section: crate::layout::Section,
    range: std::ops::Range<u64>,
    scope: &rayon::Scope<'scope>,
) -> crate::error::Result {
    scan_reloc_range_for_atom_impl::<A>(
        state, queue, resources, section, range, scope, /* extern_only= */ false,
    )
}

/// Like [`scan_reloc_range_for_atom`] but only follows extern
/// relocations — non-extern `section+offset` targets are ignored
/// for reachability purposes. Used for `__eh_frame` /
/// `__gcc_except_tab`: the sections stay loaded so the writer's
/// FDE filter has data, and CIE personality references (extern)
/// still fire symbol requests so their GOT slots get allocated,
/// but FDE→function and FDE→LSDA non-extern relocations are NOT
/// treated as reachability edges (they would otherwise activate
/// every function with an FDE, producing the 3× live-code
/// blowup).
///
/// **Complexity:** 𝒪(r) CPU where r = total relocations in the
/// section (range is unbounded, so no bucket short-circuit applies).
/// 𝒪(1) extra memory. Delegates to `scan_reloc_range_for_atom_impl`.
pub(crate) fn scan_extern_relocs_only<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    state: &crate::layout::ObjectLayoutState<'data, MachO>,
    queue: &mut crate::layout::LocalWorkQueue,
    resources: &'scope crate::layout::GraphResources<'data, '_, MachO>,
    section: crate::layout::Section,
    scope: &rayon::Scope<'scope>,
) -> crate::error::Result {
    scan_reloc_range_for_atom_impl::<A>(
        state,
        queue,
        resources,
        section,
        0..u64::MAX,
        scope,
        /* extern_only= */ true,
    )
}

/// If a non-extern reloc target lands in a merge-string / literal
/// section (S_CSTRING_LITERALS, S_8BYTE_LITERALS, etc.), stamp its
/// linear-input offset into the shared `MergeStringRefs` collector.
/// `merge_strings` (run serially after GC) consults this set to drop
/// strings/literals no live atom references.
///
/// **Complexity:** 𝒪(1) CPU and memory — one slice index check and
/// a single atomic mark on the `MergeStringRefs` bitset.
fn mark_merge_ref<'data>(
    state: &crate::layout::ObjectLayoutState<'data, MachO>,
    resources: &crate::layout::GraphResources<'data, '_, MachO>,
    tgt_sec: object::SectionIndex,
    tgt_off: u64,
) {
    use crate::resolution::SectionSlot;
    let Some(slot) = state.sections.get(tgt_sec.0) else {
        return;
    };
    if let SectionSlot::MergeStrings(merge_slot) = slot {
        resources
            .merge_string_refs
            .mark(merge_slot.linear_input_base() + tgt_off);
    }
}

/// Core reloc-scan loop for Mach-O atom GC.
///
/// **Complexity (atom-managed path):** 𝒪(r_a) CPU per call where
/// r_a = reloc count in the live atom's pre-bucketed slice (built
/// once via `SubsectionTracking.reloc_buckets` in 𝒪(r · log a) on
/// first activation, amortised 𝒪(r / a) per atom across a section).
/// Before `reloc_buckets` this was 𝒪(a · r) per section — a latent
/// quadratic that showed up on large Rust CGUs.
///
/// **Complexity (whole-section / extern-only path):** 𝒪(r) CPU
/// (range is unbounded; every reloc is visited). Additionally the
/// `is_pure_text` LSDA look-up is a single `HashMap::get` — 𝒪(1)
/// amortised.
///
/// **Memory:** 𝒪(1) extra per call (the `reloc_buckets` `OnceLock`
/// is owned by `SubsectionTracking` and persists across calls).
fn scan_reloc_range_for_atom_impl<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    state: &crate::layout::ObjectLayoutState<'data, MachO>,
    queue: &mut crate::layout::LocalWorkQueue,
    resources: &'scope crate::layout::GraphResources<'data, '_, MachO>,
    section: crate::layout::Section,
    range: std::ops::Range<u64>,
    scope: &rayon::Scope<'scope>,
    extern_only: bool,
) -> crate::error::Result {
    use object::read::macho::Nlist as _;
    use object::read::macho::Section as _;

    let le = object::Endianness::Little;
    let input_section = state
        .object
        .sections
        .get(section.index.0)
        .ok_or_else(|| crate::error!("Section index out of range"))?;
    let relocs = match input_section.relocations(le, state.object.data) {
        Ok(r) => r,
        Err(_) => return Ok(()),
    };

    // Reverse-reachability: when a text atom activates (range.start
    // points at a function symbol), check whether
    // `__compact_unwind` records an LSDA for it and queue the
    // LSDA's atom activation. That's ld64's
    // `kindNoneGroupSubordinateLSDA` direction — function's
    // liveness drives the LSDA's, not the other way around. The
    // lookup short-circuits for non-text sections (no key match)
    // and when the section was scanned with an unbounded range
    // (start=u64::MAX is the sentinel, but here range.start is
    // whatever the caller passed). Personality function GOTs
    // come from the dedicated `__compact_unwind` scan below.
    let is_pure_text = (input_section.flags.get(le) & macho::S_ATTR_PURE_INSTRUCTIONS) != 0;
    if is_pure_text {
        let lsda_map = state
            .format_specific
            .lsda_map
            .get_or_init(|| build_lsda_map(state.object));
        if let Some(&(lsda_sec, lsda_off)) = lsda_map.get(&(section.index.0 as u32, range.start)) {
            queue.push_section_activation(state.file_id, lsda_sec, lsda_off);
        }
    }

    // If the section is atom-managed and the caller handed us a narrow
    // range (i.e. one atom's `input_start..input_end`), look up the
    // pre-computed reloc bucket for that atom and iterate just those
    // indices. Building the bucket is a single linear pass over all
    // relocs in the section (O(M log A) via binary-search into the
    // sorted atom list), amortised across every atom activation. This
    // replaces the old per-atom `if r_addr < range.start || ...`
    // linear filter, which made GC O(atoms × relocs) per section.
    let atom_bucket: Option<&[u32]> = if range.end != u64::MAX
        && let Some(tracking) = state.subsection_tracking.get(&section.index.0)
    {
        let buckets = tracking.reloc_buckets.get_or_init(|| {
            let mut b: Vec<Vec<u32>> = vec![Vec::new(); tracking.atoms.len()];
            for (idx, r) in relocs.iter().enumerate() {
                let r_addr = r.info(le).r_address as u64;
                if let Some(atom_idx) = tracking.atom_index_for_offset(r_addr) {
                    b[atom_idx].push(idx as u32);
                }
            }
            b
        });
        tracking
            .atom_index_for_offset(range.start)
            .map(|idx| buckets[idx].as_slice())
    } else {
        None
    };

    let mut after_subtractor = false;
    // Pair-tracking for ADRP (`PAGE21`) + LDR/ADD (`PAGEOFF12`):
    // target byte offset = adrp_page + pageoff12_imm. We stash the
    // PAGE21 target as pending and combine on the next PAGEOFF12
    // with matching `r_symbolnum`. Reset on any other reloc so a
    // stray PAGEOFF12 can't pick up a stale page.
    let mut pending_page21: Option<(object::SectionIndex, u64, u32)> = None;

    // Macro-expand the reloc loop for both the bucketed (atom-managed)
    // and the full-slice (whole-section) paths so we avoid a
    // `Box<dyn Iterator>` allocation on every call. The body is
    // identical; only the iteration source differs.
    macro_rules! process_reloc {
        ($reloc_raw:expr) => {{
            let reloc_raw: &macho::Relocation<object::Endianness> = $reloc_raw;
            let reloc = reloc_raw.info(le);
            // `r_address` is the offset within the containing section.
            let r_addr = reloc.r_address as u64;
            if atom_bucket.is_none() && (r_addr < range.start || r_addr >= range.end) {
                // Meta relocs (ADDEND / SUBTRACTOR) can't straddle the
                // atom boundary meaningfully — if the primary is out of
                // range, skip its modifier too by resetting state.
                after_subtractor = false;
                pending_page21 = None;
                continue;
            }
            if !reloc.r_extern {
                if extern_only {
                    pending_page21 = None;
                    continue;
                }
                match reloc.r_type {
                    0 if reloc.r_length == 3 => {
                        pending_page21 = None;
                        if let Some((tgt_sec, tgt_off)) =
                            decode_non_extern_target(state.object, input_section, &reloc)
                        {
                            if state.subsection_tracking_has(&tgt_sec.0) {
                                queue.push_section_activation(state.file_id, tgt_sec, tgt_off);
                            }
                            mark_merge_ref(state, resources, tgt_sec, tgt_off);
                        }
                    }
                    3 => {
                        pending_page21 = decode_pending_page21(state.object, input_section, &reloc);
                    }
                    4 => {
                        if let Some((tgt_sec, tgt_page, sym)) = pending_page21.take()
                            && sym == reloc.r_symbolnum
                            && let Some(byte_off) =
                                decode_pageoff12_reloc(state.object, input_section, &reloc)
                            && let Some(target_sec_hdr) = state.object.sections.get(tgt_sec.0)
                        {
                            let tgt_vm = tgt_page.wrapping_add(byte_off as u64);
                            let tgt_addr = target_sec_hdr.addr.get(le);
                            let tgt_size = target_sec_hdr.size.get(le);
                            if tgt_vm >= tgt_addr {
                                let tgt_off = tgt_vm - tgt_addr;
                                if tgt_off < tgt_size {
                                    if state.subsection_tracking_has(&tgt_sec.0) {
                                        queue.push_section_activation(
                                            state.file_id,
                                            tgt_sec,
                                            tgt_off,
                                        );
                                    }
                                    mark_merge_ref(state, resources, tgt_sec, tgt_off);
                                }
                            }
                        }
                    }
                    10 => {}
                    _ => {
                        pending_page21 = None;
                    }
                }
                continue;
            }
            if reloc.r_type == 10 {
                continue;
            }
            if reloc.r_type == 1 {
                after_subtractor = true;
                continue;
            }

            let sym_idx = object::SymbolIndex(reloc.r_symbolnum as usize);
            if let Ok(sym) = state.object.symbols.symbol(sym_idx) {
                use object::read::macho::Nlist as _;
                let n_sect = sym.n_sect() as usize;
                if n_sect > 0 {
                    let tgt_sec = object::SectionIndex(n_sect - 1);
                    if let Some(tgt_hdr) = state.object.sections.get(tgt_sec.0) {
                        use object::read::macho::Section as _;
                        let tgt_addr = tgt_hdr.addr(le);
                        if let Some(tgt_off) = sym.n_value(le).checked_sub(tgt_addr) {
                            mark_merge_ref(state, resources, tgt_sec, tgt_off);
                        }
                    }
                }
            }
            let local_symbol_id = state.symbol_id_range.input_to_id(sym_idx);
            let symbol_id = resources.symbol_db.definition(local_symbol_id);

            let is_def_undef = resources.symbol_db.is_undefined(symbol_id);
            let is_ref_undef = resources.symbol_db.is_undefined(local_symbol_id);
            let flat_ns = resources.symbol_db.args.flat_namespace;
            let is_weak_def_local = state
                .object
                .symbols
                .symbol(sym_idx)
                .ok()
                .map_or(false, |s| {
                    let desc = s.n_desc(le);
                    (desc & macho::N_WEAK_DEF) != 0 && (s.n_type() & 0x0e) != 0
                });
            let flags_to_add = match reloc.r_type {
                5 | 6 | 7 => crate::value_flags::ValueFlags::GOT,
                2 if is_def_undef || (flat_ns && reloc.r_extern) || is_weak_def_local => {
                    crate::value_flags::ValueFlags::PLT | crate::value_flags::ValueFlags::GOT
                }
                0 if after_subtractor && is_ref_undef => crate::value_flags::ValueFlags::GOT,
                _ => crate::value_flags::ValueFlags::DIRECT,
            };
            after_subtractor = false;
            let atomic_flags = &resources.per_symbol_flags.get_atomic(symbol_id);
            let previous_flags = atomic_flags.fetch_or(flags_to_add);

            if !previous_flags.has_resolution() {
                queue.send_symbol_request::<A>(symbol_id, resources, scope);
            }

            let has_explicit_syslibroot = resources.symbol_db.args.syslibroot.is_some();
            if is_def_undef
                && (has_explicit_syslibroot || symbol_id != local_symbol_id)
                && !resources.symbol_db.args.dylib_symbols.is_empty()
                && !crate::platform::Args::should_allow_object_undefined(
                    resources.symbol_db.args,
                    resources.symbol_db.output_kind,
                )
            {
                let local_sym = state.object.symbols.symbol(sym_idx).ok();
                let is_weak = local_sym.map_or(false, |s| {
                    (s.n_desc(le) & (macho::N_WEAK_DEF | macho::N_WEAK_REF)) != 0
                });
                if !is_weak {
                    let sym_name = resources.symbol_db.symbol_name(symbol_id).ok();
                    let in_dylib = sym_name.map_or(false, |n| {
                        resources.symbol_db.args.dylib_symbols.contains(n.bytes())
                    });
                    let is_objc_stub =
                        sym_name.map_or(false, |n| n.bytes().starts_with(b"_objc_msgSend$"));
                    if !in_dylib && !is_objc_stub {
                        let sym_display = resources.symbol_db.symbol_name_for_display(symbol_id);
                        resources.report_error(crate::error!(
                            "undefined symbol: {}: {}",
                            state.input,
                            sym_display,
                        ));
                    }
                }
            }
        }};
    }

    if let Some(bucket) = atom_bucket {
        for &i in bucket {
            process_reloc!(&relocs[i as usize]);
        }
    } else {
        for reloc_raw in relocs {
            process_reloc!(reloc_raw);
        }
    }
    Ok(())
}

/// Platform-trait-facing entrypoint that hands the atom range to
/// [`scan_reloc_range_for_atom`]. Exists so the trait impl can
/// delegate without re-exporting the private helper.
///
/// **Complexity:** 𝒪(r_a) CPU, 𝒪(1) memory — thin wrapper;
/// all cost is in `scan_reloc_range_for_atom_impl`.
pub(crate) fn scan_atom_relocations<'data, 'scope, A: platform::Arch<Platform = MachO>>(
    state: &crate::layout::ObjectLayoutState<'data, MachO>,
    _common: &mut crate::layout::CommonGroupState<'data, MachO>,
    queue: &mut crate::layout::LocalWorkQueue,
    resources: &'scope crate::layout::GraphResources<'data, '_, MachO>,
    section: crate::layout::Section,
    atom_input_range: std::ops::Range<u64>,
    scope: &rayon::Scope<'scope>,
) -> crate::error::Result {
    scan_reloc_range_for_atom::<A>(state, queue, resources, section, atom_input_range, scope)
}

/// Computes subsection alignment padding for a single section under
/// `.subsections_via_symbols`. Each non-local symbol in the section
/// that isn't already at its section-aligned offset gets a negative
/// delta entry recording the bytes of padding that must be inserted
/// immediately before it.
///
/// Returns an empty vec for the first symbol in a section (trivially
/// aligned at offset 0), for local symbols, and for sections whose
/// alignment is already satisfied by every symbol's natural offset
/// (the common case in assembler-generated Rust objects where each
/// function is already at the next alignment boundary).
///
/// The returned vec is sorted by input offset and suitable for
/// [`linker_utils::relaxation::SectionDeltas::new`] — caller appends
/// it to the object's existing `section_relax_deltas`.
///
/// **Complexity:** Θ(n_sym + a·log a) CPU where n_sym = symbol count
/// in the object (full linear scan to collect anchors for this
/// section) and a = N_EXT symbols in the section (sort + dedup).
/// Second pass over sym_offsets is 𝒪(a). 𝒪(a) memory for
/// `sym_offsets` and result `deltas`.
pub(crate) fn compute_subsection_padding_deltas(
    file: &File<'_>,
    section_index: object::SectionIndex,
) -> Vec<(u64, i32)> {
    if !file.has_subsections_via_symbols() {
        return Vec::new();
    }
    let Some(section) = file.sections.get(section_index.0) else {
        return Vec::new();
    };
    // Only text-like subsection splitting is meaningful for the
    // fixture test (and for rust's libstd). Data sections keep their
    // raw layout — ld64 doesn't pad `__data` subsections either.
    let flags = section.flags.get(LE);
    let is_pure_text = flags & macho::S_ATTR_PURE_INSTRUCTIONS != 0;
    if !is_pure_text {
        return Vec::new();
    }

    let align_exp = section.align.get(LE);
    // align values up to 15 (2^15 = 32 KB) are reasonable; anything
    // higher is almost certainly bogus input — bail to avoid shift
    // overflow.
    if align_exp >= 32 {
        return Vec::new();
    }
    let alignment: u64 = 1u64 << align_exp;
    if alignment <= 1 {
        return Vec::new();
    }

    let section_addr = section.addr.get(LE);
    let sect_num_1based = section_index.0 as u8 + 1;

    // Collect (offset-in-section) for non-local external symbols in
    // this section. Mach-O numbers n_sect from 1.
    let mut sym_offsets: Vec<u64> = Vec::with_capacity(16);
    for sym in file.symbols.iter() {
        let n_type = sym.n_type();
        if n_type & macho::N_STAB != 0 {
            continue;
        }
        if n_type & macho::N_TYPE != macho::N_SECT {
            continue;
        }
        if sym.n_sect() != sect_num_1based {
            continue;
        }
        // `.subsections_via_symbols` splits at every non-local label;
        // `N_EXT` separates globals from file-scope locals (Apple's
        // assembler emits globals with N_EXT set). Local labels like
        // `L0` don't start subsections.
        if n_type & macho::N_EXT == 0 {
            continue;
        }
        let offset = sym.n_value(LE).wrapping_sub(section_addr);
        sym_offsets.push(offset);
    }
    sym_offsets.sort_unstable();
    sym_offsets.dedup();

    // For each symbol after the first, if its raw offset is not
    // aligned, record the required padding as an insertion delta.
    // Input offsets increase monotonically; `cumulative` tracks
    // padding already inserted so we can compute the output position
    // of earlier symbols correctly when deciding where the next one
    // should land.
    let mut deltas: Vec<(u64, i32)> = Vec::with_capacity(sym_offsets.len());
    let mut cumulative: u64 = 0;
    for &input_offset in sym_offsets.iter().skip(1) {
        let output_offset_if_unpadded = input_offset + cumulative;
        let aligned = output_offset_if_unpadded.next_multiple_of(alignment);
        if aligned > output_offset_if_unpadded {
            let pad = aligned - output_offset_if_unpadded;
            // Cap to i32 — a single subsection gap over 2 GiB is
            // pathological; refuse rather than corrupt.
            if pad > i32::MAX as u64 {
                return Vec::new();
            }
            deltas.push((input_offset, -(pad as i32)));
            cumulative += pad;
        }
    }
    deltas
}

impl<'data> platform::ObjectFile<'data> for File<'data> {
    type Platform = MachO;

    fn parse_bytes(input: &'data [u8], is_dynamic: bool) -> crate::error::Result<Self> {
        let header = macho::MachHeader64::<Endianness>::parse(input, 0)?;
        let mut commands = header.load_commands(LE, input, 0)?;

        let mut symbols = None;
        let mut sections = None;

        while let Some(command) = commands.next()? {
            if let Some(symtab_command) = command.symtab()? {
                ensure!(symbols.is_none(), "At most one symtab command expected");
                symbols = Some(symtab_command.symbols::<macho::MachHeader64<_>, _>(LE, input)?);
            } else if let Some((segment_command, segment_data)) = command.segment_64()? {
                // Mach-O object files have a single unnamed segment containing all sections.
                if sections.is_none() {
                    sections = Some(segment_command.sections(LE, segment_data)?);
                }
            }
        }

        Ok(File {
            data: input,
            symbols: symbols.ok_or("Missing symbol table")?,
            sections: sections.unwrap_or(&[]),
            flags: header.flags(LE),
        })
    }

    fn parse(
        input: &crate::input_data::InputBytes<'data>,
        args: &<Self::Platform as platform::Platform>::Args,
    ) -> crate::error::Result<Self> {
        Self::parse_bytes(input.data, false)
    }

    fn is_dynamic(&self) -> bool {
        false
    }

    fn num_symbols(&self) -> usize {
        self.symbols.len()
    }

    fn symbols_iter(&self) -> impl Iterator<Item = &'data SymtabEntry> {
        self.symbols.iter()
    }

    fn symbol(&self, index: object::SymbolIndex) -> crate::error::Result<&'data SymtabEntry> {
        self.symbols
            .symbol(index)
            .map_err(|e| error!("Symbol index {} out of range: {e}", index.0))
    }

    fn section_size(&self, header: &SectionHeader) -> crate::error::Result<u64> {
        Ok(header.0.size(LE))
    }

    fn symbol_name(&self, symbol: &SymtabEntry) -> crate::error::Result<&'data [u8]> {
        symbol
            .name(LE, self.symbols.strings())
            .map_err(|e| error!("Failed to read symbol name: {e}"))
    }

    fn num_sections(&self) -> usize {
        self.sections.len()
    }

    fn section_iter(&self) -> <MachO as platform::Platform>::SectionIterator<'data> {
        MachOSectionIter {
            inner: self.sections.iter(),
        }
    }

    fn enumerate_sections(
        &self,
    ) -> impl Iterator<Item = (object::SectionIndex, &'data SectionHeader)> {
        self.sections.iter().enumerate().map(|(i, section)| {
            // Safety: SectionHeader is #[repr(transparent)] over Section64<Endianness>
            let header: &'data SectionHeader = unsafe {
                &*(section as *const macho::Section64<Endianness> as *const SectionHeader)
            };
            (object::SectionIndex(i), header)
        })
    }

    fn section(&self, index: object::SectionIndex) -> crate::error::Result<&'data SectionHeader> {
        let section = self
            .sections
            .get(index.0)
            .ok_or_else(|| error!("Section index {} out of range", index.0))?;
        Ok(unsafe { &*(section as *const macho::Section64<Endianness> as *const SectionHeader) })
    }

    fn section_by_name(&self, name: &str) -> Option<(object::SectionIndex, &'data SectionHeader)> {
        for (i, section) in self.sections.iter().enumerate() {
            let sectname = trim_nul(section.sectname());
            if sectname == name.as_bytes() {
                let header: &'data SectionHeader = unsafe {
                    &*(section as *const macho::Section64<Endianness> as *const SectionHeader)
                };
                return Some((object::SectionIndex(i), header));
            }
        }
        None
    }

    fn symbol_section(
        &self,
        symbol: &SymtabEntry,
        index: object::SymbolIndex,
    ) -> crate::error::Result<Option<object::SectionIndex>> {
        let n_type = symbol.n_type() & macho::N_TYPE;
        if n_type == macho::N_SECT {
            // n_sect is 1-based in Mach-O
            let sect = symbol.n_sect();
            if sect == 0 {
                return Ok(None);
            }
            Ok(Some(object::SectionIndex(sect as usize - 1)))
        } else {
            Ok(None)
        }
    }

    fn symbol_value_in_section(
        &self,
        symbol: &SymtabEntry,
        section_index: object::SectionIndex,
    ) -> crate::error::Result<u64> {
        let section = &self.sections[section_index.0];
        let section_addr = section.addr.get(LE);
        let sym_value = symbol.n_value(LE);
        Ok(sym_value.wrapping_sub(section_addr))
    }

    fn symbol_versions(&self) -> &[()] {
        // Mach-O doesn't have symbol versioning
        &[]
    }

    fn dynamic_symbol_used(
        &self,
        _symbol_index: object::SymbolIndex,
        _state: &mut (),
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_sizes_dynamic(
        &self,
        _lib_name: &[u8],
        _state: &mut (),
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn apply_non_addressable_indexes_dynamic(
        &self,
        _indexes: &mut NonAddressableIndexes,
        _counts: &mut (),
        _state: &mut (),
    ) -> crate::error::Result {
        Ok(())
    }

    fn section_name(&self, section_header: &SectionHeader) -> crate::error::Result<&'data [u8]> {
        for s in self.sections {
            if std::ptr::eq(
                s as *const macho::Section64<Endianness>,
                &section_header.0 as *const macho::Section64<Endianness>,
            ) {
                let sectname = trim_nul(s.sectname());
                let segname = trim_nul(&s.segname);
                // __const appears in both __TEXT (read-only, no pointers) and
                // __DATA (has pointer relocations). Qualify with segment name
                // so they map to different output sections.
                if sectname == b"__const" && segname == b"__TEXT" {
                    return Ok(b"__text_const");
                }
                return Ok(sectname);
            }
        }
        Err(error!("Section header not found in file's section table"))
    }

    fn raw_section_data(&self, section: &SectionHeader) -> crate::error::Result<&'data [u8]> {
        let offset = section.0.offset(LE) as usize;
        let size = section.0.size(LE) as usize;
        if size == 0 {
            return Ok(&[]);
        }
        self.data
            .get(offset..offset + size)
            .ok_or_else(|| error!("Section data out of range"))
    }

    fn section_data(
        &self,
        section: &SectionHeader,
        _member: &bumpalo_herd::Member<'data>,
        _loaded_metrics: &crate::resolution::LoadedMetrics,
    ) -> crate::error::Result<&'data [u8]> {
        // Mach-O sections are never compressed
        self.raw_section_data(section)
    }

    fn copy_section_data(&self, section: &SectionHeader, out: &mut [u8]) -> crate::error::Result {
        let data = self.raw_section_data(section)?;
        out[..data.len()].copy_from_slice(data);
        Ok(())
    }

    fn section_data_cow(
        &self,
        section: &SectionHeader,
    ) -> crate::error::Result<std::borrow::Cow<'data, [u8]>> {
        Ok(std::borrow::Cow::Borrowed(self.raw_section_data(section)?))
    }

    fn section_alignment(&self, section: &SectionHeader) -> crate::error::Result<u64> {
        let raw_align = 1u64 << section.0.align(LE);
        // __thread_vars descriptors contain pointers and need 8-byte alignment,
        // but rustc/clang emit them with align=1. Force minimum 8-byte alignment
        // to match ld64 behaviour.
        let sec_type = section.0.flags(LE) & 0xFF;
        if sec_type == 0x13 {
            // S_THREAD_LOCAL_VARIABLES
            Ok(raw_align.max(8))
        } else {
            Ok(raw_align)
        }
    }

    fn relocations(
        &self,
        index: object::SectionIndex,
        _relocations: &(),
    ) -> crate::error::Result<RelocationList<'data>> {
        let section = self
            .sections
            .get(index.0)
            .ok_or_else(|| error!("Section index {} out of range for relocations", index.0))?;
        let relocs = section
            .relocations(LE, self.data)
            .map_err(|e| error!("Failed to read relocations: {e}"))?;
        Ok(RelocationList {
            relocations: relocs,
        })
    }

    fn parse_relocations(&self) -> crate::error::Result<()> {
        // Mach-O relocations are stored per-section, accessed via `relocations` method
        Ok(())
    }

    fn symbol_version_debug(&self, _symbol_index: object::SymbolIndex) -> Option<String> {
        None
    }

    fn section_display_name(&self, index: object::SectionIndex) -> std::borrow::Cow<'data, str> {
        if let Some(section) = self.sections.get(index.0) {
            let segname = String::from_utf8_lossy(trim_nul(section.segname()));
            let sectname = String::from_utf8_lossy(trim_nul(section.sectname()));
            std::borrow::Cow::Owned(format!("{segname},{sectname}"))
        } else {
            std::borrow::Cow::Borrowed("<unknown>")
        }
    }

    fn is_symbol_in_common_section(&self, symbol: &SymtabEntry) -> bool {
        let n_type = symbol.n_type() & macho::N_TYPE;
        if n_type != macho::N_SECT {
            return false;
        }
        let sect = symbol.n_sect();
        if sect == 0 {
            return false;
        }
        if let Some(section) = self.sections.get(sect as usize - 1) {
            trim_nul(section.sectname()) == b"__common"
        } else {
            false
        }
    }

    fn dynamic_tag_values(&self) -> Option<DynamicTagValues<'data>> {
        None
    }

    fn get_version_names(&self) -> crate::error::Result<()> {
        Ok(())
    }

    fn get_symbol_name_and_version(
        &self,
        symbol: &SymtabEntry,
        _local_index: usize,
        _version_names: &(),
    ) -> crate::error::Result<RawSymbolName<'data>> {
        let name = symbol
            .name(LE, self.symbols.strings())
            .map_err(|e| error!("Failed to read symbol name: {e}"))?;
        Ok(RawSymbolName { name })
    }

    fn should_enforce_undefined(
        &self,
        _resources: &crate::layout::GraphResources<'data, '_, MachO>,
    ) -> bool {
        true
    }

    fn verneed_table(&self) -> crate::error::Result<VerneedTable<'data>> {
        Ok(VerneedTable { _phantom: &[] })
    }

    fn process_gnu_note_section(
        &self,
        _state: &mut ObjectLayoutStateExt,
        _section_index: object::SectionIndex,
    ) -> crate::error::Result {
        Ok(())
    }

    fn dynamic_tags(&self) -> crate::error::Result<&'data [()]> {
        Ok(&[])
    }
}

// -- SectionHeader trait impls --

impl platform::SectionHeader for SectionHeader {
    fn is_alloc(&self) -> bool {
        // In Mach-O, all sections in loadable segments are "allocated"
        true
    }

    fn is_writable(&self) -> bool {
        // Check segment name: __DATA and __DATA_CONST segments are writable
        let segname = trim_nul(self.0.segname());
        segname.starts_with(b"__DATA")
    }

    fn is_executable(&self) -> bool {
        let flags = self.0.flags(LE);
        (flags & macho::S_ATTR_PURE_INSTRUCTIONS) != 0
            || (flags & macho::S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    fn is_tls(&self) -> bool {
        // Only __thread_data and __thread_bss are actual TLS data sections.
        // __thread_vars is the descriptor table that lives in regular DATA —
        // it must NOT be marked as TLS so it gets a normal section resolution.
        let sectname = trim_nul(self.0.sectname());
        sectname == b"__thread_data" || sectname == b"__thread_bss"
    }

    fn is_merge_section(&self) -> bool {
        let flags = self.0.flags(LE) & macho::SECTION_TYPE;
        flags == macho::S_CSTRING_LITERALS
            || flags == macho::S_LITERAL_POINTERS
            || flags == macho::S_4BYTE_LITERALS
            || flags == macho::S_8BYTE_LITERALS
            || flags == 0x0E // S_16BYTE_LITERALS (not in object crate)
    }

    fn is_strings(&self) -> bool {
        let flags = self.0.flags(LE) & macho::SECTION_TYPE;
        flags == macho::S_CSTRING_LITERALS
    }

    fn merge_stride(&self) -> Option<u32> {
        // Mach-O fixed-size literal pools: each entry is independent,
        // content-hashed, deduplicated. ld64 does the same via
        // `FixedSizeSection` (parsers/macho_relocatable_file.cpp ~445).
        let flags = self.0.flags(LE) & macho::SECTION_TYPE;
        match flags {
            macho::S_4BYTE_LITERALS => Some(4),
            macho::S_8BYTE_LITERALS => Some(8),
            0x0E /* S_16BYTE_LITERALS */ => Some(16),
            _ => None,
        }
    }

    fn should_retain(&self) -> bool {
        let sec_type = self.0.flags(LE) & macho::SECTION_TYPE;
        let sectname = trim_nul(self.0.sectname());
        // Constructor/destructor function pointer arrays.
        if sec_type == macho::S_MOD_INIT_FUNC_POINTERS
            || sec_type == macho::S_MOD_TERM_FUNC_POINTERS
        {
            return true;
        }
        // Exception handling sections needed for unwinding.
        if sectname == b"__eh_frame" || sectname == b"__gcc_except_tab" {
            return true;
        }
        // Thread-local sections: always retain. No link-time reloc
        // points directly into `__thread_data`'s bytes — the TLS
        // descriptor in `__thread_vars` refers to them via an offset
        // computed at link time from `__thread_data_start +
        // tls_offset`. That means no reachability edge activates
        // the input section, so wild's GC leaves it `Unloaded`, the
        // resolution assigns no address, and the writer skips the
        // copy — every thread starts with all-zero TLS storage
        // instead of the initial values Rust emitted.
        //
        // Observed in `midnight-node-toolkit::lib`: `thread_local!`
        // cells with non-zero init state (e.g. Arc descriptors) were
        // NULL at thread start, and every worker thread SIGSEGV'd
        // in `std::sys::thread_local::native::eager::destroy+76`
        // (atomic decrement through a NULL Arc inner pointer).
        //
        // S_THREAD_LOCAL_REGULAR=0x11 (`__thread_data`),
        // S_THREAD_LOCAL_ZEROFILL=0x12 (`__thread_bss`),
        // S_THREAD_LOCAL_VARIABLES=0x13 (`__thread_vars`),
        // S_THREAD_LOCAL_VARIABLE_POINTERS=0x14,
        // S_THREAD_LOCAL_INIT_FUNCTION_POINTERS=0x15.
        if (0x11..=0x15).contains(&sec_type) {
            return true;
        }
        false
    }

    fn should_exclude(&self) -> bool {
        let segname = trim_nul(self.0.segname());
        let sectname = trim_nul(self.0.sectname());
        // Debug sections in __DWARF segment are not loaded
        if segname == b"__DWARF" {
            return true;
        }
        // __LD segment contains linker-private data (e.g. __compact_unwind)
        // that must be consumed by the linker, not emitted to output.
        if segname == b"__LD" {
            return true;
        }
        false
    }

    fn is_group(&self) -> bool {
        false
    }

    fn is_note(&self) -> bool {
        false
    }

    fn is_prog_bits(&self) -> bool {
        let section_type = self.0.flags(LE) & macho::SECTION_TYPE;
        section_type == macho::S_REGULAR
            || section_type == macho::S_CSTRING_LITERALS
            || section_type == macho::S_4BYTE_LITERALS
            || section_type == macho::S_8BYTE_LITERALS
            || section_type == 0x0E // S_16BYTE_LITERALS
            // S_THREAD_LOCAL_REGULAR (0x11): `__thread_data` carries
            // the INITIAL values for Rust `thread_local!{}` cells
            // (state tags, Arc descriptors, …). Previously omitted
            // here, so wild treated `__thread_data` as zerofill and
            // never copied the input bytes into the output. At
            // runtime, threads started with all-zero TLS storage,
            // so the first `thread_local!` access — which runs
            // drop logic through a cell header — NULL-deref'd in
            // `std::sys::thread_local::native::eager::destroy`.
            // Observed in `midnight-node-toolkit::lib` tests where
            // every `commands::*` test SIGSEGV'd on worker-thread
            // exit.
            || section_type == 0x11 // S_THREAD_LOCAL_REGULAR
    }

    fn is_no_bits(&self) -> bool {
        let section_type = self.0.flags(LE) & macho::SECTION_TYPE;
        section_type == macho::S_ZEROFILL || section_type == macho::S_GB_ZEROFILL
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionType(u32);

impl platform::SectionType for SectionType {
    fn is_rela(&self) -> bool {
        false
    }

    fn is_rel(&self) -> bool {
        false
    }

    fn is_symtab(&self) -> bool {
        false
    }

    fn is_strtab(&self) -> bool {
        false
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionFlags(u32);

impl SectionFlags {
    pub(crate) fn from_header(header: &SectionHeader) -> Self {
        SectionFlags(header.0.flags(LE))
    }
}

impl platform::SectionFlags for SectionFlags {
    fn is_alloc(self) -> bool {
        // All Mach-O sections are allocated
        true
    }
}

impl platform::Symbol for SymtabEntry {
    fn as_common(&self) -> Option<platform::CommonSymbol> {
        // In Mach-O, common symbols are N_UNDF | N_EXT with n_value > 0
        let n_type = self.n_type();
        if (n_type & macho::N_TYPE) == macho::N_UNDF
            && (n_type & macho::N_EXT) != 0
            && self.n_value(LE) > 0
        {
            // GET_COMM_ALIGN: alignment is encoded in bits 8-11 of n_desc
            let alignment_val = u64::from((self.n_desc(LE) >> 8) & 0x0f);
            let alignment = crate::alignment::Alignment::new(if alignment_val > 0 {
                1u64 << alignment_val
            } else {
                1
            })
            .unwrap_or(crate::alignment::MIN);
            let size = alignment.align_up(self.n_value(LE));
            let output_section_id = crate::output_section_id::BSS;
            let part_id = output_section_id.part_id_with_alignment(alignment);
            Some(platform::CommonSymbol { size, part_id })
        } else {
            None
        }
    }

    fn is_undefined(&self) -> bool {
        let n_type = self.n_type();
        // Not a stab, and type is N_UNDF, but NOT a common symbol
        // (common symbols are N_UNDF | N_EXT with n_value > 0)
        (n_type & macho::N_STAB) == 0
            && (n_type & macho::N_TYPE) == macho::N_UNDF
            && !self.is_common()
    }

    fn is_local(&self) -> bool {
        let n_type = self.n_type();
        // Not external and not a stab entry
        (n_type & macho::N_STAB) == 0 && (n_type & macho::N_EXT) == 0
    }

    fn is_absolute(&self) -> bool {
        (self.n_type() & macho::N_TYPE) == macho::N_ABS
    }

    fn is_weak(&self) -> bool {
        (self.n_desc(LE) & (macho::N_WEAK_DEF | macho::N_WEAK_REF)) != 0
    }

    fn visibility(&self) -> crate::symbol_db::Visibility {
        let n_type = self.n_type();
        if (n_type & macho::N_PEXT) != 0 {
            crate::symbol_db::Visibility::Hidden
        } else if (n_type & macho::N_EXT) != 0 {
            crate::symbol_db::Visibility::Default
        } else {
            crate::symbol_db::Visibility::Hidden
        }
    }

    fn value(&self) -> u64 {
        self.n_value(LE)
    }

    fn size(&self) -> u64 {
        // Mach-O symbols don't have a size field
        0
    }

    fn section_index(&self) -> object::SectionIndex {
        let n_type = self.n_type() & macho::N_TYPE;
        if n_type == macho::N_SECT {
            // n_sect is 1-based in Mach-O
            let sect = self.n_sect();
            if sect > 0 {
                return object::SectionIndex(sect as usize - 1);
            }
        }
        object::SectionIndex(0)
    }

    fn has_name(&self) -> bool {
        self.n_strx(LE) != 0
    }

    fn debug_string(&self) -> String {
        format!(
            "Nlist64 {{ n_type: 0x{:02x}, n_sect: {}, n_desc: 0x{:04x}, n_value: 0x{:x} }}",
            self.n_type(),
            self.n_sect(),
            self.n_desc(LE),
            self.n_value(LE),
        )
    }

    fn is_tls(&self) -> bool {
        // In Mach-O, TLS symbols reference __thread_vars section
        false
    }

    fn is_interposable(&self) -> bool {
        // Mach-O two-level namespace means symbols are generally not interposable
        false
    }

    fn is_func(&self) -> bool {
        // Mach-O doesn't have an explicit function type in nlist.
        // We'd need to check the section type, but for now return false.
        false
    }

    fn is_ifunc(&self) -> bool {
        false
    }

    fn is_hidden(&self) -> bool {
        (self.n_type() & macho::N_PEXT) != 0
    }

    fn is_gnu_unique(&self) -> bool {
        false
    }
}

// -- SectionAttributes --

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SectionAttributes {
    flags: u32,
    segname: [u8; 16],
}

impl platform::SectionAttributes for SectionAttributes {
    type Platform = MachO;

    fn merge(&mut self, rhs: Self) {
        self.flags |= rhs.flags;
    }

    fn apply(
        &self,
        _output_sections: &mut crate::output_section_id::OutputSections<MachO>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) {
    }

    fn is_null(&self) -> bool {
        false
    }

    fn is_alloc(&self) -> bool {
        true
    }

    fn is_executable(&self) -> bool {
        (self.flags & macho::S_ATTR_PURE_INSTRUCTIONS) != 0
            || (self.flags & macho::S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn is_writable(&self) -> bool {
        self.segname.starts_with(b"__DATA")
    }

    fn is_no_bits(&self) -> bool {
        let section_type = self.flags & macho::SECTION_TYPE;
        section_type == macho::S_ZEROFILL || section_type == macho::S_GB_ZEROFILL
    }

    fn flags(&self) -> SectionFlags {
        SectionFlags(self.flags)
    }

    fn ty(&self) -> SectionType {
        SectionType(self.flags & macho::SECTION_TYPE)
    }

    fn set_to_default_type(&mut self) {
        self.flags = (self.flags & !macho::SECTION_TYPE) | macho::S_REGULAR;
    }
}

// -- Other platform type stubs --

pub(crate) struct NonAddressableIndexes {}

impl platform::NonAddressableIndexes for NonAddressableIndexes {
    fn new<P: platform::Platform>(_symbol_db: &crate::symbol_db::SymbolDb<P>) -> Self {
        NonAddressableIndexes {}
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct SegmentType {}

impl platform::SegmentType for SegmentType {}

#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct ProgramSegmentDef {
    pub(crate) writable: bool,
    pub(crate) executable: bool,
}

/// Mach-O on-disk size constants used when pre-computing the header
/// reservation in `macho_header_bytes`. All numbers match the layout
/// emitted by `macho_writer::write_headers`.
///
/// Keep in sync with the writer: if you add a new load command there,
/// add its size contribution below or `-ld64_compat` will under/over-
/// reserve and code will be overwritten at runtime.
mod macho_layout {
    /// `mach_header_64`: magic+cpu+sub+type+ncmds+cmdsize+flags+reserved.
    pub(super) const MACH_HEADER_64_BYTES: u64 = 32;
    /// `LC_SEGMENT_64` header (without per-section `section_64` entries).
    pub(super) const LC_SEGMENT_64_HEADER_BYTES: u64 = 72;
    /// Per-`section_64` entry appended after `LC_SEGMENT_64` header.
    pub(super) const SECTION_64_BYTES: u64 = 80;
    /// `LC_DYLD_CHAINED_FIXUPS` / `LC_DYLD_EXPORTS_TRIE`: cmd+size+off+size.
    pub(super) const LC_LINKEDIT_DATA_BYTES: u64 = 16;
    /// `LC_SYMTAB`: cmd+size+symoff+nsyms+stroff+strsize.
    pub(super) const LC_SYMTAB_BYTES: u64 = 24;
    /// `LC_DYSYMTAB`: cmd+size+18 × u32.
    pub(super) const LC_DYSYMTAB_BYTES: u64 = 80;
    /// `LC_UUID`: cmd+size+16 bytes of UUID.
    pub(super) const LC_UUID_BYTES: u64 = 24;
    /// `LC_BUILD_VERSION`: cmd+size+platform+minos+sdk+ntools+tool+toolv.
    pub(super) const LC_BUILD_VERSION_BYTES: u64 = 32;
    /// `LC_SOURCE_VERSION`: cmd+size+u64 packed version.
    pub(super) const LC_SOURCE_VERSION_BYTES: u64 = 16;
    /// `LC_MAIN` (entry_point_command): cmd+size+entryoff+stacksize.
    pub(super) const LC_MAIN_BYTES: u64 = 24;
    /// `LC_FUNCTION_STARTS` / `LC_DATA_IN_CODE` (linkedit_data_command).
    pub(super) const LC_LINKEDIT_TABLE_BYTES: u64 = 16;
    /// `dylib_command` fixed prefix before the variable-length path.
    pub(super) const DYLIB_COMMAND_FIXED_BYTES: u64 = 24;
    /// `dylinker_command` / `rpath_command` / `sub_framework_command`
    /// fixed prefix before the variable-length path.
    pub(super) const DYLINKER_COMMAND_FIXED_BYTES: u64 = 12;
    /// dyld interpreter path that `LC_LOAD_DYLINKER` always points at.
    pub(super) const DYLD_PATH_LEN: u64 = b"/usr/lib/dyld".len() as u64;
    /// Path for the implicit libSystem.B.dylib dependency.
    pub(super) const LIBSYSTEM_PATH_LEN: u64 = b"/usr/lib/libSystem.B.dylib".len() as u64;
    /// `codesign --force` appends a new `linkedit_data_command` for the
    /// ad-hoc signature during `write_direct`. Reserve it up front so the
    /// post-link signer doesn't need to shift `__text`.
    pub(super) const LC_CODE_SIGNATURE_BYTES: u64 = 16;
    /// ld64 default `-headerpad` — 32 bytes of trailing slack so `install_name_tool`
    /// and similar can rewrite LCs without relocating later content.
    pub(super) const DEFAULT_HEADERPAD_BYTES: u64 = 32;
    /// ARM64 instructions are 4 bytes; `__text` must start on a 4-byte boundary.
    pub(super) const TEXT_ALIGNMENT_BYTES: u64 = 4;

    /// `S_SYMBOL_STUBS` type nibble — used by the writer to identify
    /// `__stubs` and force its alignment.
    pub(crate) const S_SYMBOL_STUBS_TYPE: u32 = 0x08;
}

/// Compute the exact byte count of the Mach-O header region we're going to
/// emit: mach header plus every load command, each with its own size rule,
/// plus default headerpad and room for the ad-hoc `LC_CODE_SIGNATURE` that
/// `codesign` appends post-link. Used under `-ld64_compat` to reserve the
/// minimum possible `FILE_HEADER` allocation so `__text` lands in the
/// first 16KB page just like ld64's output.
///
/// Must stay in sync with `macho_writer::write_headers` — whenever that
/// emits a new LC, add it here or the layout will under/over-reserve.
///
/// **Complexity:** 𝒪(S + d + e) CPU where S = number of output
/// sections (one linear scan via `num_sections()`), d = extra dylibs,
/// e = `-add_empty_section` entries (grouped via `BTreeMap` in 𝒪(e·log e)).
/// All arithmetic is 𝒪(1) per item. 𝒪(e) memory for `empty_by_seg`.
fn macho_header_bytes(
    _header_info: &crate::layout::HeaderInfo,
    output_sections: &crate::output_section_id::OutputSections<MachO>,
    args: &MachOArgs,
    total_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
) -> u64 {
    use crate::output_section_id;
    use macho_layout::*;

    // Only sections with accumulated content are counted — the writer
    // drops zero-size sections in its iteration loop, so including them
    // here would over-reserve and push __text past ld64's offset.
    let has_content = |id: output_section_id::OutputSectionId| -> bool {
        let range = id.part_id_range();
        let mut total: u64 = 0;
        let (start, end) = (range.start.as_usize(), range.end.as_usize());
        for i in start..end {
            total += *total_sizes.get(crate::part_id::PartId::from_u32(i as u32));
        }
        total > 0
    };
    let is_kept = |id: output_section_id::OutputSectionId| -> bool {
        output_sections.output_index_of_section(id).is_some() && has_content(id)
    };
    let in_text = |id: output_section_id::OutputSectionId| -> bool {
        matches!(
            id,
            output_section_id::TEXT
                | output_section_id::PLT_GOT
                | output_section_id::GCC_EXCEPT_TABLE
                | output_section_id::EH_FRAME
                | output_section_id::RODATA
                | output_section_id::COMMENT
                | output_section_id::DATA_REL_RO
        )
    };
    let in_data = |id: output_section_id::OutputSectionId| -> bool {
        matches!(
            id,
            output_section_id::DATA
                | output_section_id::CSTRING
                | output_section_id::GOT
                | output_section_id::PREINIT_ARRAY
                | output_section_id::INIT_ARRAY
                | output_section_id::FINI_ARRAY
                | output_section_id::TDATA
                | output_section_id::TBSS
                | output_section_id::BSS
        )
    };

    // Types that ld64 (and wild under `-ld64_compat`) route into
    // __DATA_CONST when mixed with writable sections. Must stay in sync
    // with the partition logic in `macho_writer::write_headers`.
    let is_const_data_section = |id: output_section_id::OutputSectionId| -> bool {
        matches!(
            id,
            output_section_id::GOT | output_section_id::INIT_ARRAY | output_section_id::FINI_ARRAY
        )
    };
    let is_writable_data_section = |id: output_section_id::OutputSectionId| -> bool {
        matches!(
            id,
            output_section_id::DATA
                | output_section_id::CSTRING
                | output_section_id::PREINIT_ARRAY
                | output_section_id::TDATA
                | output_section_id::TBSS
                | output_section_id::BSS
        )
    };

    let mut text_sects: u64 = 0;
    let mut data_const_sects: u64 = 0;
    let mut data_writable_sects: u64 = 0;
    for i in 0..output_sections.num_sections() {
        let id = output_section_id::OutputSectionId::from_usize(i);
        if !is_kept(id) {
            continue;
        }
        if in_text(id) {
            text_sects += 1;
        } else if is_const_data_section(id) {
            data_const_sects += 1;
        } else if is_writable_data_section(id) {
            data_writable_sects += 1;
        }
    }
    // `__unwind_info` is emitted as the `COMMENT` output section
    // (see `macho_writer::macho_section_info`), which `in_text`
    // already counts above when COMMENT has content — no extra
    // slot needed here.
    // -sectcreate injects extra sections into their declared segment.
    for (segname, _, _) in &args.sectcreate {
        if segname.starts_with(b"__TEXT\0") {
            text_sects += 1;
        } else if segname.starts_with(b"__DATA\0") {
            // -sectcreate always targets the writable __DATA segment
            // in wild's emission path.
            data_writable_sects += 1;
        }
    }

    let is_exe = !args.is_dylib && !args.is_bundle && !args.is_relocatable;
    let align8 = |v: u64| (v + 7) & !7u64;
    let seg_lc = |nsects: u64| LC_SEGMENT_64_HEADER_BYTES + SECTION_64_BYTES * nsects;

    let mut sz: u64 = MACH_HEADER_64_BYTES;

    // Segment load commands.
    //
    // The DATA region splits into TWO segment commands (__DATA_CONST +
    // __DATA) when both kinds of sections are present — RO-after-init
    // for const pointers, RW for everything else. Reserve for both so
    // the header estimate doesn't leave `__text` overlapping into the
    // load-command region.
    if is_exe {
        sz += seg_lc(0); // __PAGEZERO
    }
    sz += seg_lc(text_sects); // __TEXT
    let split_data = data_const_sects > 0 && data_writable_sects > 0;
    if split_data {
        sz += seg_lc(data_const_sects); // __DATA_CONST
        sz += seg_lc(data_writable_sects); // __DATA
    } else if data_const_sects + data_writable_sects > 0 {
        sz += seg_lc(data_const_sects + data_writable_sects); // __DATA (or renamed)
    }
    sz += seg_lc(0); // __LINKEDIT

    // Empty segments from -add_empty_section. Group by segname.
    use std::collections::BTreeMap;
    let mut empty_by_seg: BTreeMap<[u8; 16], u64> = BTreeMap::new();
    for (segname, _) in &args.empty_sections {
        *empty_by_seg.entry(*segname).or_insert(0) += 1;
    }
    for (_, n) in &empty_by_seg {
        sz += seg_lc(*n);
    }

    // Fixed LCs.
    sz += LC_LINKEDIT_DATA_BYTES; // LC_DYLD_CHAINED_FIXUPS
    sz += LC_LINKEDIT_DATA_BYTES; // LC_DYLD_EXPORTS_TRIE
    sz += LC_SYMTAB_BYTES;
    sz += LC_DYSYMTAB_BYTES;

    if !args.is_dylib {
        sz += align8(DYLINKER_COMMAND_FIXED_BYTES + DYLD_PATH_LEN + 1);
    }
    sz += LC_UUID_BYTES;
    sz += LC_BUILD_VERSION_BYTES;
    sz += LC_SOURCE_VERSION_BYTES;

    if args.is_dylib {
        let name_len = args.install_name.as_ref().map(|n| n.len()).unwrap_or(0) as u64;
        sz += align8(DYLIB_COMMAND_FIXED_BYTES + name_len + 1); // LC_ID_DYLIB
    } else if !args.is_bundle {
        sz += LC_MAIN_BYTES;
    }

    // libSystem.B.dylib dependency is implicit for every executable/dylib.
    sz += align8(DYLIB_COMMAND_FIXED_BYTES + LIBSYSTEM_PATH_LEN + 1);
    for (path, _) in &args.extra_dylibs {
        sz += align8(DYLIB_COMMAND_FIXED_BYTES + path.len() as u64 + 1);
    }
    for rpath in &args.rpaths {
        sz += align8(DYLINKER_COMMAND_FIXED_BYTES + rpath.len() as u64 + 1);
    }
    if let Some(name) = args.umbrella.as_ref() {
        sz += align8(DYLINKER_COMMAND_FIXED_BYTES + name.len() as u64 + 1);
    }
    if !args.no_function_starts {
        sz += LC_LINKEDIT_TABLE_BYTES;
    }
    if !args.no_data_in_code {
        sz += LC_LINKEDIT_TABLE_BYTES;
    }

    // Reserve slack for codesign's appended LC + ld64-equivalent default
    // headerpad. Without this, the post-link ad-hoc signer has no room
    // to add LC_CODE_SIGNATURE and `__text` would need to shift.
    if !args.no_adhoc_codesign {
        sz += LC_CODE_SIGNATURE_BYTES;
    }
    sz += DEFAULT_HEADERPAD_BYTES;

    // __text must start on a 4-byte boundary (ARM64 instructions).
    (sz + TEXT_ALIGNMENT_BYTES - 1) & !(TEXT_ALIGNMENT_BYTES - 1)
}

/// __TEXT segment: r-x, contains headers + code + read-only data
const TEXT_SEGMENT_DEF: ProgramSegmentDef = ProgramSegmentDef {
    writable: false,
    executable: true,
};

/// __DATA segment: rw-, contains writable data + GOT + BSS
const DATA_SEGMENT_DEF: ProgramSegmentDef = ProgramSegmentDef {
    writable: true,
    executable: false,
};

const MACHO_SEGMENT_DEFS: &[ProgramSegmentDef] = &[TEXT_SEGMENT_DEF, DATA_SEGMENT_DEF];

impl std::fmt::Display for ProgramSegmentDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.executable {
            write!(f, "__TEXT")
        } else {
            write!(f, "__DATA")
        }
    }
}

impl platform::ProgramSegmentDef for ProgramSegmentDef {
    type Platform = MachO;

    fn is_writable(self) -> bool {
        self.writable
    }

    fn is_executable(self) -> bool {
        self.executable
    }

    fn always_keep(self) -> bool {
        true // Both __TEXT and __DATA are always emitted
    }

    fn is_loadable(self) -> bool {
        true // Both are loadable
    }

    fn is_stack(self) -> bool {
        false
    }

    fn is_tls(self) -> bool {
        false
    }

    fn order_key(self) -> usize {
        if self.executable { 0 } else { 1 }
    }

    fn should_include_section(
        self,
        section_info: &crate::output_section_id::SectionOutputInfo<MachO>,
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        let attrs = &section_info.section_attributes;
        if !attrs.is_alloc() {
            return false;
        }
        if self.writable {
            attrs.is_writable()
        } else {
            !attrs.is_writable()
        }
    }
}

pub(crate) struct BuiltInSectionDetails {}

impl platform::BuiltInSectionDetails for BuiltInSectionDetails {}

/// Mach-O specific resolution data attached to each resolved symbol.
#[derive(Debug, Copy, Clone, Default)]
pub(crate) struct MachOResolutionExt {
    /// GOT entry address (if the symbol needs a GOT slot).
    pub(crate) got_address: Option<u64>,
    /// PLT stub address (if the symbol needs a dynamic call stub).
    pub(crate) plt_address: Option<u64>,
}

#[derive(Default, Debug, Clone, Copy)]
pub(crate) struct DynamicTagValues<'data> {
    _phantom: &'data [u8],
}

#[derive(Debug)]
pub(crate) struct RelocationList<'data> {
    pub(crate) relocations: &'data [macho::Relocation<Endianness>],
}

impl<'data> platform::RelocationList<'data> for RelocationList<'data> {
    fn num_relocations(&self) -> usize {
        self.relocations.len()
    }
}

impl<'data> platform::DynamicTagValues<'data> for DynamicTagValues<'data> {
    fn lib_name(&self, _input: &crate::input_data::InputRef<'data>) -> &'data [u8] {
        b""
    }
}

#[derive(Debug)]
pub(crate) struct RawSymbolName<'data> {
    pub(crate) name: &'data [u8],
}

impl<'data> platform::RawSymbolName<'data> for RawSymbolName<'data> {
    fn parse(bytes: &'data [u8]) -> Self {
        RawSymbolName { name: bytes }
    }

    fn name(&self) -> &'data [u8] {
        self.name
    }

    fn version_name(&self) -> Option<&'data [u8]> {
        None
    }

    fn is_default(&self) -> bool {
        true
    }
}

impl std::fmt::Display for RawSymbolName<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.name))
    }
}

pub(crate) struct VerneedTable<'data> {
    _phantom: &'data [u8],
}

impl<'data> platform::VerneedTable<'data> for VerneedTable<'data> {
    fn version_name(&self, _local_symbol_index: object::SymbolIndex) -> Option<&'data [u8]> {
        None
    }
}

/// Iterator adapter to cast Section64 refs to SectionHeader refs.
pub(crate) struct MachOSectionIter<'data> {
    inner: core::slice::Iter<'data, macho::Section64<Endianness>>,
}

impl<'data> Iterator for MachOSectionIter<'data> {
    type Item = &'data SectionHeader;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|s| unsafe {
            &*(s as *const macho::Section64<Endianness> as *const SectionHeader)
        })
    }
}

impl platform::Platform for MachO {
    type File<'data> = File<'data>;
    type SymtabEntry = SymtabEntry;
    type SectionHeader = SectionHeader;
    type SectionFlags = SectionFlags;
    type SectionAttributes = SectionAttributes;
    type SectionType = SectionType;
    type SegmentType = SegmentType;
    type ProgramSegmentDef = ProgramSegmentDef;
    type BuiltInSectionDetails = BuiltInSectionDetails;
    type RelocationSections = ();
    type DynamicEntry = ();
    type DynamicSymbolDefinitionExt = ();
    type NonAddressableIndexes = NonAddressableIndexes;
    type NonAddressableCounts = ();
    type EpilogueLayoutExt = ();
    type GroupLayoutExt = ();
    type CommonGroupStateExt = ();
    type ArchIdentifier = ();
    type Args = MachOArgs;
    type ResolutionExt = MachOResolutionExt;
    type SymbolVersionIndex = ();
    type LayoutExt = ();
    type SymtabPrecount = crate::macho_writer::MachOSymtabPrecount;
    type SectionIterator<'data> = MachOSectionIter<'data>;
    type DynamicTagValues<'data> = DynamicTagValues<'data>;
    type RelocationList<'data> = RelocationList<'data>;
    type DynamicLayoutStateExt<'data> = ();
    type DynamicLayoutExt<'data> = ();
    type LayoutResourcesExt<'data> = ();
    type PreludeLayoutStateExt = ();
    type PreludeLayoutExt = ();
    type ObjectLayoutStateExt<'data> = ObjectLayoutStateExt;
    type RawSymbolName<'data> = RawSymbolName<'data>;
    type VersionNames<'data> = ();
    type VerneedTable<'data> = VerneedTable<'data>;
    type SymtabShndxEntry = u32;

    fn link_for_arch<'data>(
        linker: &'data crate::Linker,
        args: &'data Self::Args,
    ) -> crate::error::Result<crate::LinkerOutput<'data>> {
        linker.link_for_arch::<MachO, crate::macho_aarch64::MachOAArch64>(args)
    }

    fn write_output_file<'data, A: platform::Arch<Platform = Self>>(
        output: &mut crate::file_writer::Output,
        layout: &crate::layout::Layout<'data, Self>,
    ) -> crate::error::Result {
        crate::macho_writer::write_output::<A>(output, layout)
    }

    fn precount_symtab<'data>(layout: &crate::layout::Layout<'data, Self>) -> Self::SymtabPrecount {
        crate::macho_writer::precount_symtab(layout)
    }

    // Mach-O's final output size depends on data not built until after
    // layout's set_size call window (segment_layouts, stab counts,
    // codesign-blob reservation). Return `None` so `layout.rs` skips
    // the pre-set; `write_output` calls `output.set_size` itself.
    fn output_file_size_at_layout(
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> Option<u64> {
        None
    }

    fn section_attributes(header: &Self::SectionHeader) -> Self::SectionAttributes {
        SectionAttributes {
            flags: header.0.flags(LE),
            segname: *header.0.segname(),
        }
    }

    fn apply_force_keep_sections(
        keep_sections: &mut crate::output_section_map::OutputSectionMap<bool>,
        args: &Self::Args,
    ) {
        *keep_sections.get_mut(crate::output_section_id::INIT_ARRAY) = true;
        *keep_sections.get_mut(crate::output_section_id::FINI_ARRAY) = true;
        // Exception handling sections needed for stack unwinding.
        *keep_sections.get_mut(crate::output_section_id::EH_FRAME) = true;
        *keep_sections.get_mut(crate::output_section_id::GCC_EXCEPT_TABLE) = true;
        // Always keep `RELRO_PADDING` so the layout pass will expand it
        // to the next page boundary between the immutable-pointer
        // sections (`__got`, `__mod_init_func`) and writable data
        // (`__data`, `__bss`, TLS). ld64 puts these on their own 16 KB
        // page (__DATA_CONST segment) separate from writable data
        // (__DATA segment); wild's writer splits the merged DATA region
        // at this boundary. Without the padding section there's no
        // boundary to split on, and the trailing BSS-on-its-own-page
        // layout reintroduces the `vmsize > filesize` gap that macOS
        // 14+ fills with garbage (see `project_zerocopy_bss_bug`).
        //
        // NOTE: force_keep runs before we know which sections have
        // actual content, so we keep `RELRO_PADDING` unconditionally.
        // For the pure-const case (hello-puts: __got only) the padding
        // section still gets placed in the output order but the layout
        // pass leaves it zero-size because `mem_offset` is already at
        // the target page boundary.
        let _ = args;
        *keep_sections.get_mut(crate::output_section_id::RELRO_PADDING) = true;
    }

    fn is_zero_sized_section_content(
        _section_id: crate::output_section_id::OutputSectionId,
    ) -> bool {
        false
    }

    fn compute_subsection_padding_deltas<'data>(
        file: &<Self as platform::Platform>::File<'data>,
        section_index: object::SectionIndex,
    ) -> Vec<(u64, i32)> {
        compute_subsection_padding_deltas(file, section_index)
    }

    fn compute_atoms<'data>(
        file: &<Self as platform::Platform>::File<'data>,
        section_index: object::SectionIndex,
    ) -> Vec<crate::layout::Atom> {
        compute_atoms(file, section_index)
    }

    fn scan_atom_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        state: &crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        section: crate::layout::Section,
        atom_input_range: std::ops::Range<u64>,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        scan_atom_relocations::<A>(
            state,
            common,
            queue,
            resources,
            section,
            atom_input_range,
            scope,
        )
    }

    fn built_in_section_details() -> &'static [Self::BuiltInSectionDetails] {
        &[]
    }

    fn finalise_group_layout(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> Self::GroupLayoutExt {
    }

    fn frame_data_base_address(
        _memory_offsets: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> u64 {
        0
    }

    fn start_memory_address(output_kind: crate::output_kind::OutputKind) -> u64 {
        if output_kind == crate::output_kind::OutputKind::SharedObject
            || output_kind.is_relocatable()
        {
            0 // dylibs and relocatables have no PAGEZERO
        } else {
            0x1_0000_0000 // PAGEZERO size for executables
        }
    }

    fn finalise_find_required_sections(_groups: &[crate::layout::GroupState<Self>]) {}

    fn activate_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) {
    }

    fn pre_finalise_sizes_prelude<'scope, 'data>(
        _prelude: &mut crate::layout::PreludeLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _resources: &crate::layout::GraphResources<'data, 'scope, Self>,
    ) {
    }

    fn finalise_sizes_dynamic<'data>(
        _object: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn finalise_object_sizes<'data>(
        object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        common: &mut crate::layout::CommonGroupState<'data, Self>,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
    ) -> crate::error::Result {
        compact_atom_managed_sections(object, common, output_sections);
        Ok(())
    }

    fn finalise_object_layout<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn finalise_layout_dynamic<'data>(
        _state: &mut crate::layout::DynamicLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
        _resolutions_out: &mut crate::layout::ResolutionWriter<Self>,
    ) -> crate::error::Result<Self::DynamicLayoutExt<'data>> {
        Ok(())
    }

    fn take_dynsym_index(
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _section_layouts: &crate::output_section_map::OutputSectionMap<
            crate::layout::OutputRecordLayout,
        >,
    ) -> crate::error::Result<u32> {
        // Mach-O doesn't use dynsym indices. Return 1 to satisfy NonZeroU32.
        // The value is unused in the Mach-O writer.
        Ok(1)
    }

    fn compute_object_addresses<'data>(
        _object: &crate::layout::ObjectLayoutState<'data, Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
    }

    fn layout_resources_ext<'data>(
        _groups: &[crate::grouping::Group<'data, Self>],
    ) -> Self::LayoutResourcesExt<'data> {
    }

    fn load_object_section_relocations<'data, 'scope, A: platform::Arch<Platform = Self>>(
        state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        queue: &mut crate::layout::LocalWorkQueue,
        resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        section: crate::layout::Section,
        scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        let le = object::Endianness::Little;

        // `__eh_frame` stays loaded (force-retained via
        // `should_retain`) so the writer's per-function FDE
        // filter has data, but we do NOT scan its relocations
        // for reachability: FDE→function PC-relative edges would
        // activate every function with an FDE and invert GC
        // direction. Personality-function GOT slots come from
        // the `__compact_unwind` scan below; LSDA reachability
        // comes from the reverse-edge LSDA map built by
        // `build_lsda_map` and consulted per-atom inside
        // `scan_reloc_range_for_atom_impl`.
        let sectname_bytes = state
            .object
            .sections
            .get(section.index.0)
            .map(|s| crate::macho::trim_nul(s.sectname()))
            .unwrap_or(&[]);
        let is_eh_frame = sectname_bytes == b"__eh_frame";

        // Under `.subsections_via_symbols`, wild defers the main
        // reloc loop to per-atom activation. Applies to any section
        // for which `compute_atoms` returned atoms — today that's
        // pure-text, `__const`, and `__gcc_except_tab`. The
        // `__compact_unwind` pass below still runs unconditionally.
        let atom_managed = state.subsection_tracking_has(&section.index.0);
        if !atom_managed && !is_eh_frame {
            scan_reloc_range_for_atom::<A>(state, queue, resources, section, 0..u64::MAX, scope)?;
        }

        // For `__eh_frame` we don't want FDE PC relocs to activate
        // every function (that inverts GC direction and re-pulls
        // the world in). But the CIE `POINTER_TO_GOT` reloc on the
        // personality pointer *must* allocate a GOT slot —
        // otherwise the writer's `apply_relocations` fallback
        // emits the raw function VA into the CIE personality
        // field, `scan_eh_frame_fde_offsets` then reads back a
        // bogus "GOT VM" value, and `__unwind_info` personality
        // indices point at rubbish. Walk the section's relocations
        // and, for every `ARM64_RELOC_POINTER_TO_GOT` (type 7,
        // length 2, pc-rel) with an extern target, set the GOT
        // flag + send a symbol request. FDE `pc_begin` relocs
        // (type UNSIGNED, r_length=3, not pc-rel) are skipped, so
        // we don't pull functions in via this pass.
        if is_eh_frame {
            if let Some(sec_obj) = state.object.sections.get(section.index.0) {
                if let Ok(relocs) = sec_obj.relocations(le, state.object.data) {
                    for r in relocs {
                        let ri = r.info(le);
                        if ri.r_type != 7 || ri.r_length != 2 || !ri.r_pcrel || !ri.r_extern {
                            continue;
                        }
                        let sym_idx = object::SymbolIndex(ri.r_symbolnum as usize);
                        let local_id = state.symbol_id_range.input_to_id(sym_idx);
                        let sym_id = resources.symbol_db.definition(local_id);
                        let atomic = resources.per_symbol_flags.get_atomic(sym_id);
                        let prev = atomic.fetch_or(crate::value_flags::ValueFlags::GOT);
                        if !prev.has_resolution() {
                            queue.send_symbol_request::<A>(sym_id, resources, scope);
                        }
                    }
                }
            }
        }

        // Also scan __compact_unwind for personality function references that
        // need GOT entries. The personality reloc is at offset 16 within each
        // 32-byte entry. We request GOT for undefined personality symbols so
        // they get GOT slots allocated during layout.
        //
        // This scan is per-object, not per-section — gate it on an
        // AtomicBool so we don't re-parse the full load-command stream
        // for every activated section. `Relaxed` is fine: the scan
        // only drives atomic symbol-flag fetch_ors and queue pushes,
        // both idempotent; the flag is purely a "skip" gate.
        if !state
            .format_specific
            .compact_unwind_scanned
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            use object::read::macho::MachHeader as _;
            use object::read::macho::Segment as _;
            if let Ok(header) =
                object::macho::MachHeader64::<object::Endianness>::parse(state.object.data, 0)
            {
                if let Ok(mut cmds) = header.load_commands(le, state.object.data, 0) {
                    while let Ok(Some(cmd)) = cmds.next() {
                        let Ok(Some((seg, seg_data))) = cmd.segment_64() else {
                            continue;
                        };
                        let Ok(sections) = seg.sections(le, seg_data) else {
                            continue;
                        };
                        for sec in sections {
                            let sec_segname = crate::macho::trim_nul(&sec.segname);
                            let sectname = crate::macho::trim_nul(&sec.sectname);
                            if sec_segname != b"__LD" || sectname != b"__compact_unwind" {
                                continue;
                            }
                            let relocs = match sec.relocations(le, state.object.data) {
                                Ok(r) => r,
                                Err(_) => continue,
                            };
                            // Compute the __compact_unwind data slice
                            // once — used when decoding non-extern
                            // personality refs (which encode the
                            // target VM address inline at offset 16).
                            let cu_off = sec.offset.get(le) as usize;
                            let cu_size = sec.size.get(le) as usize;
                            let cu_data = state
                                .object
                                .data
                                .get(cu_off..cu_off.checked_add(cu_size).unwrap_or(0));
                            for r in relocs {
                                let ri = r.info(le);
                                if ri.r_type != 0 {
                                    continue;
                                }
                                // Personality is at offset 16 within each 32-byte entry.
                                if ri.r_address as usize % 32 != 16 {
                                    continue;
                                }
                                if ri.r_extern {
                                    // Extern personality reference —
                                    // ask the resolver and ensure the
                                    // GOT flag is set so a slot is
                                    // allocated during layout.
                                    let sym_idx = object::SymbolIndex(ri.r_symbolnum as usize);
                                    let local_id = state.symbol_id_range.input_to_id(sym_idx);
                                    let sym_id = resources.symbol_db.definition(local_id);
                                    let atomic = &resources.per_symbol_flags.get_atomic(sym_id);
                                    let prev = atomic.fetch_or(crate::value_flags::ValueFlags::GOT);
                                    if !prev.has_resolution() {
                                        queue.send_symbol_request::<A>(sym_id, resources, scope);
                                    }
                                } else if let Some(cu_data) = cu_data
                                    && let Some((tgt_sec, tgt_off)) =
                                        decode_non_extern_section_offset(
                                            state.object,
                                            cu_data,
                                            &ri,
                                            ri.r_address as usize,
                                        )
                                {
                                    // Non-extern personality: the
                                    // personality function is defined
                                    // in this same object (e.g.
                                    // `_rust_eh_personality` in
                                    // libstd's CGU). Queue its atom
                                    // activation so the text atom
                                    // lights up and the resolver can
                                    // give it a GOT slot.
                                    queue.push_section_activation(state.file_id, tgt_sec, tgt_off);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn create_dynamic_symbol_definition<'data>(
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        symbol_id: crate::symbol_db::SymbolId,
    ) -> crate::error::Result<crate::layout::DynamicSymbolDefinition<'data, Self>> {
        let name = symbol_db.symbol_name(symbol_id)?.bytes();
        Ok(crate::layout::DynamicSymbolDefinition {
            symbol_id,
            name,
            format_specific: (),
        })
    }

    fn update_segment_keep_list(
        _program_segments: &crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
        _keep_segments: &mut [bool],
        _args: &Self::Args,
    ) {
        // Default keep logic is sufficient -- segments with sections are kept automatically.
        // The pipeline sets keep_segments[0] = true for the first segment (__TEXT).
    }

    fn program_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        MACHO_SEGMENT_DEFS
    }

    fn unconditional_segment_defs() -> &'static [Self::ProgramSegmentDef] {
        &[]
    }

    fn create_linker_defined_symbols(
        symbols: &mut crate::parsing::InternalSymbolsBuilder,
        output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        use crate::parsing::InternalSymDefInfo;
        use crate::parsing::SymbolPlacement;

        // `___dso_handle` is a magic symbol every image must provide.
        // The C/C++ runtime passes it to `__cxa_atexit` / `atexit` so
        // destructors can be scoped to the image they belong to (and
        // are unregistered when the image unloads). ld64 synthesizes
        // it at the image's load base (the mach header address).
        //
        // Without this, C/C++ translation units with
        // `__attribute__((destructor))` or non-trivial global
        // destructors fail to link — the reference comes in as
        // undefined from the object file and no input dylib defines
        // it. Substrate-wasm-builder (via `wasm-opt`, `cxx`,
        // `link-cplusplus`) triggers this in the midnight-node
        // runtime build-script.
        // Note: Mach-O symtab entries carry a leading `_` prefix on
        // top of the C name, so the `__dso_handle` variable is
        // named `___dso_handle` in both input objects and output
        // symtab (three underscores).
        symbols
            .add_symbol(InternalSymDefInfo::new(
                SymbolPlacement::LoadBaseAddress,
                b"___dso_handle",
            ))
            .hide();

        // `__mh_execute_header` / `__mh_dylib_header` / `__mh_bundle_header`
        // point at the image's mach header. `_dyld_get_image_header`
        // and related APIs resolve it back from an address. ld64
        // always emits one of these, matched to the filetype.
        if output_kind.is_executable() {
            symbols.add_symbol(InternalSymDefInfo::new(
                SymbolPlacement::LoadBaseAddress,
                b"__mh_execute_header",
            ));
        } else if output_kind.is_shared_object() {
            symbols
                .add_symbol(InternalSymDefInfo::new(
                    SymbolPlacement::LoadBaseAddress,
                    b"__mh_dylib_header",
                ))
                .hide();
        } else {
            symbols
                .add_symbol(InternalSymDefInfo::new(
                    SymbolPlacement::LoadBaseAddress,
                    b"__mh_bundle_header",
                ))
                .hide();
        }
    }

    fn built_in_section_infos<'data>()
    -> Vec<crate::output_section_id::SectionOutputInfo<'data, Self>> {
        use crate::layout_rules::SectionKind;
        use crate::output_section_id::NUM_BUILT_IN_SECTIONS;
        use crate::output_section_id::SectionName;
        use crate::output_section_id::SectionOutputInfo;

        let mut infos: Vec<SectionOutputInfo<'data, Self>> =
            Vec::with_capacity(NUM_BUILT_IN_SECTIONS);
        for _ in 0..NUM_BUILT_IN_SECTIONS {
            infos.push(SectionOutputInfo {
                kind: SectionKind::Primary(SectionName(b"")),
                section_attributes: SectionAttributes::default(),
                min_alignment: crate::alignment::MIN,
                location: None,
                secondary_order: None,
            });
        }

        // Provide names/attributes for the regular sections we care about
        infos[crate::output_section_id::TEXT.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__text")),
            section_attributes: SectionAttributes {
                flags: macho::S_REGULAR | macho::S_ATTR_PURE_INSTRUCTIONS,
                segname: *b"__TEXT\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::RODATA.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__rodata")),
            section_attributes: SectionAttributes::default(),
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::DATA.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__data")),
            section_attributes: SectionAttributes {
                flags: macho::S_REGULAR,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::GOT.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__got")),
            section_attributes: SectionAttributes {
                flags: 0x06, // S_NON_LAZY_SYMBOL_POINTERS
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::GOT_ENTRY,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::TDATA.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__thread_data")),
            section_attributes: SectionAttributes {
                flags: macho::S_THREAD_LOCAL_REGULAR,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            // Let the input content drive the alignment: ld64 reports
            // what the source section actually needs (e.g. 2^2 for an
            // `int` TLS variable), so setting a floor of 2^3 would
            // inflate the emitted section header.
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        // PREINIT_ARRAY is wild's routing target for `__thread_vars` —
        // the TLV descriptor table. It lives in `__DATA` alongside the
        // TLS backing storage; without the explicit `segname` the
        // default SectionAttributes say "not writable", and the layout
        // pass then treats it as an RO section that forces a segment
        // break between it and `__thread_data`/`__bss`.
        infos[crate::output_section_id::PREINIT_ARRAY.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__thread_vars")),
            section_attributes: SectionAttributes {
                flags: macho::S_THREAD_LOCAL_VARIABLES,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        // Same story for `__mod_init_func` (INIT_ARRAY) and
        // `__mod_term_func` (FINI_ARRAY): ld64 puts both in __DATA_CONST
        // (we carve that under compat); layout still needs them tagged
        // writable so they don't force a segment break between the
        // immutable-pointer sections and the writable ones.
        infos[crate::output_section_id::INIT_ARRAY.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__mod_init_func")),
            section_attributes: SectionAttributes {
                flags: macho::S_MOD_INIT_FUNC_POINTERS,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::FINI_ARRAY.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__mod_term_func")),
            section_attributes: SectionAttributes {
                flags: macho::S_MOD_TERM_FUNC_POINTERS,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        // GOT needs the same treatment — without the segname tag it is
        // considered non-writable at layout time, making its placement
        // relative to __data trigger segment breaks.
        infos[crate::output_section_id::GOT.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__got")),
            section_attributes: SectionAttributes {
                flags: macho::S_NON_LAZY_SYMBOL_POINTERS,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::GOT_ENTRY,
            location: None,
            secondary_order: None,
        };
        // CSTRING for __DATA,__const (writable data with pointer relocs).
        infos[crate::output_section_id::CSTRING.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__const")),
            section_attributes: SectionAttributes {
                flags: macho::S_REGULAR,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        // TBSS pairs with TDATA for uninitialised TLS — same writable DATA.
        infos[crate::output_section_id::TBSS.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__thread_bss")),
            section_attributes: SectionAttributes {
                flags: macho::S_THREAD_LOCAL_ZEROFILL,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos[crate::output_section_id::BSS.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"__bss")),
            section_attributes: SectionAttributes {
                flags: macho::S_ZEROFILL,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        // RELRO_PADDING is ELF-borrowed: the layout pass expands it to
        // the next page so `__DATA_CONST` ends on a segment boundary
        // (see `-ld64_compat` path). Without overriding the default
        // SectionAttributes (segname=zeros → is_writable=false), the
        // output-order builder treats RELRO_PADDING as non-writable
        // and forces an RW-segment cut around it, which for pure-data
        // fixtures like `tls` pushes `__thread_data` onto its own
        // page. Tagging it as a writable __DATA section keeps it
        // in-segment; the page-expand behaviour still fires via the
        // explicit `section_id == RELRO_PADDING` branch in layout.rs.
        infos[crate::output_section_id::RELRO_PADDING.as_usize()] = SectionOutputInfo {
            kind: SectionKind::Primary(SectionName(b"")),
            section_attributes: SectionAttributes {
                flags: 0,
                segname: *b"__DATA\0\0\0\0\0\0\0\0\0\0",
            },
            min_alignment: crate::alignment::MIN,
            location: None,
            secondary_order: None,
        };
        infos
    }

    fn create_layout_properties<'data, 'states, 'files, A: platform::Arch<Platform = Self>>(
        _args: &Self::Args,
        _objects: impl Iterator<Item = &'files Self::File<'data>>,
        _states: impl Iterator<Item = &'states Self::ObjectLayoutStateExt<'data>> + Clone,
    ) -> crate::error::Result<Self::LayoutExt>
    where
        'data: 'files,
        'data: 'states,
    {
        Ok(())
    }

    fn load_exception_frame_data<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _eh_frame_section_index: object::SectionIndex,
        _resources: &'scope crate::layout::GraphResources<'data, '_, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn non_empty_section_loaded<'data, 'scope, A: platform::Arch<Platform = Self>>(
        _object: &mut crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _queue: &mut crate::layout::LocalWorkQueue,
        _unloaded: crate::resolution::UnloadedSection,
        _resources: &'scope crate::layout::GraphResources<'data, 'scope, Self>,
        _scope: &rayon::Scope<'scope>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn new_epilogue_layout(
        _args: &Self::Args,
        _output_kind: crate::output_kind::OutputKind,
        _dynamic_symbol_definitions: &mut [crate::layout::DynamicSymbolDefinition<'_, Self>],
    ) -> Self::EpilogueLayoutExt {
    }

    fn apply_non_addressable_indexes_epilogue(
        _counts: &mut Self::NonAddressableCounts,
        _state: &mut Self::EpilogueLayoutExt,
    ) {
    }

    fn apply_non_addressable_indexes<'data, 'groups>(
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _counts: &Self::NonAddressableCounts,
        _mem_sizes_iter: impl Iterator<
            Item = &'groups mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        >,
    ) {
    }

    fn finalise_sizes_epilogue<'data>(
        _state: &mut Self::EpilogueLayoutExt,
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_definitions: &[crate::layout::DynamicSymbolDefinition<'data, Self>],
        _properties: &Self::LayoutExt,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn finalise_sizes_all<'data>(
        _mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
    ) {
    }

    fn apply_late_size_adjustments_epilogue(
        _state: &mut Self::EpilogueLayoutExt,
        current_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        extra_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
        _args: &Self::Args,
        symbol_db: &crate::symbol_db::SymbolDb<'_, Self>,
    ) -> crate::error::Result {
        // Reserve space at the end of __TEXT for `__unwind_info`.
        // Wild repurposes the otherwise-empty `COMMENT` output
        // section as the trailing `__unwind_info` slot on Mach-O
        // (see `macho_writer::macho_section_info`). Before this, the
        // writer placed `__unwind_info` opportunistically in the
        // incidental gap between the last TEXT section and the
        // page-aligned TEXT segment end — if the gap was zero or
        // smaller than the computed section, the whole section was
        // silently dropped and every subsequent panic died with
        // `_URC_END_OF_STACK`.
        let _ = current_sizes;
        let aligned = unwind_info_reserved_bytes(symbol_db);
        if aligned == 0 {
            return Ok(());
        }
        extra_sizes.increment(
            crate::output_section_id::COMMENT
                .part_id_with_alignment(crate::alignment::Alignment { exponent: 2 }),
            aligned,
        );
        Ok(())
    }

    fn finalise_layout_epilogue<'data>(
        _epilogue_state: &mut Self::EpilogueLayoutExt,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _common_state: &Self::LayoutExt,
        _dynsym_start_index: u32,
        _dynamic_symbol_defs: &[crate::layout::DynamicSymbolDefinition<Self>],
    ) -> crate::error::Result {
        // Bump `memory_offsets` for the unwind-info reservation that
        // `apply_late_size_adjustments_epilogue` merged into
        // `common.mem_sizes`. Without this, the debug-build
        // `OffsetVerifier` (layout.rs:1688) sees expected == starting
        // + sizes but memory_offsets never advanced for the COMMENT
        // part, and bails with "Part #237 bumped by 0x0 requested
        // size: 0x…". The release build ships the binary correctly —
        // the writer re-derives the section size from
        // `build_unwind_info_section` — so this is only about
        // keeping the debug-mode invariant honest.
        let aligned = unwind_info_reserved_bytes(symbol_db);
        if aligned > 0 {
            memory_offsets.increment(
                crate::output_section_id::COMMENT
                    .part_id_with_alignment(crate::alignment::Alignment { exponent: 2 }),
                aligned,
            );
        }
        Ok(())
    }

    fn is_symbol_non_interposable<'data>(
        _object: &Self::File<'data>,
        args: &Self::Args,
        _sym: &Self::SymtabEntry,
        _output_kind: crate::output_kind::OutputKind,
        _export_list: Option<&crate::export_list::ExportList>,
        _lib_name: &[u8],
        _archive_semantics: bool,
        _is_undefined: bool,
    ) -> bool {
        // With -flat_namespace, symbols are interposable (dyld searches all dylibs).
        !args.flat_namespace
    }

    fn adjust_output_section_alignments(
        output_sections: &mut crate::output_section_id::OutputSections<Self>,
        args: &Self::Args,
    ) {
        let _ = args;
        // ld64 emits `__DATA_CONST` (containing `__got` and other
        // immutable pointer sections) on its own 16 KB page, with the
        // writable `__DATA` segment (`__data`, `__bss`, TLS data, …)
        // on the next page. Only bump when both categories are kept —
        // bumping unconditionally would push `__data` onto a second
        // page in executables that have no immutable-pointer content
        // at all (hello-c, hello-global) and inflate their `__data`
        // alignment to 2^14, which breaks the non-mixed bit-for-bit
        // matches we already have.
        use crate::output_section_id;
        let has_const = output_sections
            .output_index_of_section(output_section_id::GOT)
            .is_some()
            || output_sections
                .output_index_of_section(output_section_id::INIT_ARRAY)
                .is_some()
            || output_sections
                .output_index_of_section(output_section_id::FINI_ARRAY)
                .is_some();
        let has_writable = output_sections
            .output_index_of_section(output_section_id::DATA)
            .is_some()
            || output_sections
                .output_index_of_section(output_section_id::BSS)
                .is_some()
            || output_sections
                .output_index_of_section(output_section_id::TDATA)
                .is_some()
            || output_sections
                .output_index_of_section(output_section_id::TBSS)
                .is_some();
        // The `output_index_of_section` checks above always return
        // None at this point in the pipeline (indexes are populated
        // later in `determine_header_sizes`), so this hook is
        // currently a no-op. Keeping the structure lets us wire in
        // per-link alignment bumps from a real "which sections have
        // content" signal if one becomes available before layout.
        let _ = (has_const, has_writable);
    }

    fn adjust_alignments_after_sizing(
        output_sections: &mut crate::output_section_id::OutputSections<Self>,
        section_part_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
        _args: &Self::Args,
    ) {
        // rdar://24221680 — `__thread_data` and `__thread_bss` must share
        // the same alignment so dyld's per-thread TLV buffer (allocated
        // via `::malloc(initialContentSize)`) lays out every variable at
        // `var.addr - tdata.addr` and respects each variable's declared
        // alignment. Promoting both sections to `max(tdata.align,
        // tbss.align)` makes the natural Mach-O section-alignment gap
        // between them equal to `round_up(tdata.size, max_align)`, so
        // the TLV template offset becomes a single subtraction with no
        // ad-hoc padding (see `tlv_template_offset` in macho_writer).
        use crate::output_section_id;
        let tdata_align = section_part_sizes
            .max_alignment(output_section_id::TDATA.part_id_range(), output_sections);
        let tbss_align = section_part_sizes
            .max_alignment(output_section_id::TBSS.part_id_range(), output_sections);
        let common = tdata_align.max(tbss_align);
        output_sections.bump_min_alignment(output_section_id::TDATA, common);
        output_sections.bump_min_alignment(output_section_id::TBSS, common);
    }

    fn allocate_header_sizes(
        _prelude: &mut crate::layout::PreludeLayoutState<Self>,
        sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        header_info: &crate::layout::HeaderInfo,
        output_sections: &crate::output_section_id::OutputSections<Self>,
        args: &Self::Args,
        total_sizes: &crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) {
        // Default: reserve a full 16KB page. Historically wild has always
        // done this — it's simple and safely fits any plausible header. The
        // downside: __text ends up at segment offset 0x4000, pushing the
        // __TEXT segment into a second VM page just so the code can have
        // its own page. ld64 packs header + code into one page (__text.addr
        // ~0x328 for a tiny C main). Under -ld64_compat we compute the
        // actual byte count of the load commands we're going to emit and
        // reserve exactly that, so the single-page layout falls out.
        // ld64_compat tries to pack header + code into the first 16 KB
        // page by precomputing the exact LC byte count. The precomputation
        // only covers executables — dylib LC counting for unusual
        // sections (.rustc, __const in __DATA, __thread_vars) under-
        // counts and leaves __text overlapping the load commands, which
        // codesign then rejects with "internal error in Code Signing
        // subsystem". For dylibs, fall back to the safe 16 KB page.
        //
        // Tiny C dylibs would pack fine but we can't distinguish them
        // from Rust-std-linked dylibs at this stage in the pipeline —
        // so the fallback applies to all dylibs under compat. Bit-for-
        // bit dylib parity would need `data_writable_sects` /
        // `data_const_sects` classification to be correct for every
        // OutputSectionId that can land in __DATA, which currently
        // misses .rustc, __thread_vars and the __DATA-side __const.
        if args.is_dylib {
            sizes.increment(crate::part_id::FILE_HEADER, 0x4000);
            return;
        }
        sizes.increment(
            crate::part_id::FILE_HEADER,
            macho_header_bytes(header_info, output_sections, args, total_sizes),
        );
    }

    fn finalise_sizes_for_symbol<'data>(
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _symbol_id: crate::symbol_db::SymbolId,
        _flags: crate::value_flags::ValueFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_resolution(
        flags: crate::value_flags::ValueFlags,
        mem_sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _output_kind: crate::output_kind::OutputKind,
        _args: &Self::Args,
    ) {
        if flags.needs_plt() {
            // Mach-O stubs are 12 bytes (adrp + ldr + br)
            mem_sizes.increment(crate::part_id::PLT_GOT, 12);
            // Each stub needs a GOT entry (8 bytes) for the dyld bind target
            mem_sizes.increment(crate::part_id::GOT, 8);
        } else if flags.needs_got() {
            mem_sizes.increment(crate::part_id::GOT, 8);
        }
    }

    fn allocate_object_symtab_space<'data>(
        _state: &crate::layout::ObjectLayoutState<'data, Self>,
        _common: &mut crate::layout::CommonGroupState<'data, Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<'data, Self>,
        _per_symbol_flags: &crate::value_flags::AtomicPerSymbolFlags,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_internal_symbol(
        _symbol_id: crate::symbol_db::SymbolId,
        _def_info: &crate::parsing::InternalSymDefInfo,
        _sizes: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) -> crate::error::Result {
        Ok(())
    }

    fn allocate_prelude(
        _common: &mut crate::layout::CommonGroupState<Self>,
        _symbol_db: &crate::symbol_db::SymbolDb<Self>,
    ) {
    }

    fn finalise_prelude_layout<'data>(
        _prelude: &crate::layout::PreludeLayoutState<Self>,
        _memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
        _resources: &crate::layout::FinaliseLayoutResources<'_, 'data, Self>,
    ) -> crate::error::Result<Self::PreludeLayoutExt> {
        Ok(())
    }

    fn create_resolution(
        flags: crate::value_flags::ValueFlags,
        raw_value: u64,
        dynamic_symbol_index: Option<std::num::NonZeroU32>,
        memory_offsets: &mut crate::output_section_part_map::OutputSectionPartMap<u64>,
    ) -> crate::layout::Resolution<Self> {
        let mut got_address = None;
        let mut plt_address = None;

        if flags.needs_plt() {
            let got_addr = *memory_offsets.get(crate::part_id::GOT);
            *memory_offsets.get_mut(crate::part_id::GOT) += 8;
            got_address = Some(got_addr);

            let plt_addr = *memory_offsets.get(crate::part_id::PLT_GOT);
            *memory_offsets.get_mut(crate::part_id::PLT_GOT) += 12;
            plt_address = Some(plt_addr);
        } else if flags.needs_got() {
            let got_addr = *memory_offsets.get(crate::part_id::GOT);
            *memory_offsets.get_mut(crate::part_id::GOT) += 8;
            got_address = Some(got_addr);
        }

        crate::layout::Resolution {
            raw_value,
            dynamic_symbol_index,
            flags,
            format_specific: MachOResolutionExt {
                got_address,
                plt_address,
            },
        }
    }

    fn raw_symbol_name<'data>(
        name_bytes: &'data [u8],
        _verneed_table: &Self::VerneedTable<'data>,
        _symbol_index: object::SymbolIndex,
    ) -> Self::RawSymbolName<'data> {
        RawSymbolName { name: name_bytes }
    }

    fn default_layout_rules() -> &'static [crate::layout_rules::SectionRule<'static>] {
        MACHO_SECTION_RULES
    }

    fn build_output_order_and_program_segments<'data>(
        custom: &crate::output_section_id::CustomSectionIds,
        output_kind: OutputKind,
        output_sections: &crate::output_section_id::OutputSections<'data, Self>,
        secondary: &crate::output_section_map::OutputSectionMap<
            Vec<crate::output_section_id::OutputSectionId>,
        >,
        args: &Self::Args,
    ) -> (
        crate::output_section_id::OutputOrder,
        crate::program_segments::ProgramSegments<Self::ProgramSegmentDef>,
    ) {
        use crate::output_section_id;
        let mut builder = crate::output_section_id::OutputOrderBuilder::<Self>::new(
            output_kind,
            output_sections,
            secondary,
        );

        // __TEXT segment (r-x). Follow ld64's layout so bit-for-bit
        // compat tests match section addresses exactly:
        //   __text → __stubs → __cstring → __text_const → __gcc_except_tab →
        //   __eh_frame → __unwind_info (trailing slot).
        builder.add_section(output_section_id::FILE_HEADER);
        builder.add_section(output_section_id::TEXT);
        builder.add_sections(&custom.exec);
        builder.add_section(output_section_id::PLT_GOT); // __stubs
        builder.add_section(output_section_id::RODATA); // __cstring
        builder.add_section(output_section_id::DATA_REL_RO); // __text_const
        builder.add_sections(&custom.ro);
        builder.add_section(output_section_id::GCC_EXCEPT_TABLE);
        builder.add_section(output_section_id::EH_FRAME);
        builder.add_section(output_section_id::COMMENT); // __unwind_info — trailing slot

        // __DATA segment(s) (rw-): writable data, GOT, BSS.
        //
        // Immutable-pointer sections (__got, __mod_init_func,
        // __mod_term_func) come first so they land in the __DATA_CONST
        // segment that the writer carves off the low end of the DATA
        // region; __data / __bss / __thread_* follow. The zero-size
        // `RELRO_PADDING` between them is expanded at layout time to
        // the next 16 KB page, giving the writer a clean cut point.
        //
        // This layout is structurally required — without the split,
        // __DATA ends up with `vmsize > filesize` (BSS spilling onto a
        // page that has no file backing). macOS 14+ then fills that
        // gap from `fileoff + filesize` in the file (which is
        // LC_DYLD_CHAINED_FIXUPS content) instead of zeros, and
        // zero-init'd Rust statics come up as garbage. See
        // `project_zerocopy_bss_bug`.
        builder.add_section(output_section_id::INIT_ARRAY); // __mod_init_func
        builder.add_section(output_section_id::FINI_ARRAY); // __mod_term_func
        builder.add_section(output_section_id::GOT);
        // Zero-size padding that the layout pass expands to the next
        // 16 KB page so `__data` (writable) lands in its own segment.
        // `macho_writer::write_headers` then splits the merged DATA
        // region at this boundary into __DATA_CONST + __DATA.
        builder.add_section(output_section_id::RELRO_PADDING);
        builder.add_section(output_section_id::DATA);
        builder.add_section(output_section_id::CSTRING); // __DATA,__const
        builder.add_section(output_section_id::PREINIT_ARRAY); // __thread_vars
        builder.add_sections(&custom.data);
        builder.add_section(output_section_id::TDATA);
        builder.add_section(output_section_id::TBSS);
        builder.add_section(output_section_id::BSS);
        builder.add_sections(&custom.bss);

        builder.build()
    }
}

const MACHO_SECTION_RULES: &[crate::layout_rules::SectionRule<'static>] = {
    use crate::layout_rules::SectionRule;
    use crate::output_section_id;
    &[
        SectionRule::exact_section(b"__text", output_section_id::TEXT),
        SectionRule::exact_section(b"__stubs", output_section_id::TEXT),
        SectionRule::exact_section(b"__stub_helper", output_section_id::TEXT),
        // Each Mach-O section gets a dedicated output section ID where possible.
        // Sharing output section IDs between sections with different names can
        // cause data overlap when the layout pipeline assigns overlapping parts.
        // __DATA,__const has pointer relocations — give it CSTRING (unused regular
        // section on Mach-O) to keep it separate from __data (both align 8).
        SectionRule::exact_section(b"__const", output_section_id::CSTRING),
        SectionRule::exact_section(b"__text_const", output_section_id::DATA_REL_RO),
        SectionRule::exact_section(b"__cstring", output_section_id::RODATA),
        // Fixed-size literal pools fold into `__TEXT,__const` — this
        // matches ld64's `InternalState::FinalSection::outputSection`
        // at `ld.cpp:213–221` which redirects all literal4/8/16 atoms
        // to `_s_TEXT_const`. The merge pipeline still deduplicates
        // per-stride (see `SectionHeader::merge_stride`); the output
        // just lands in the same `__const` section alongside
        // `__text_const` inputs rather than in its own `__literal8`.
        SectionRule::exact_section(b"__literal4", output_section_id::DATA_REL_RO),
        SectionRule::exact_section(b"__literal8", output_section_id::DATA_REL_RO),
        SectionRule::exact_section(b"__literal16", output_section_id::DATA_REL_RO),
        SectionRule::exact_section(b"__data", output_section_id::DATA),
        SectionRule::exact_section(b"__la_symbol_ptr", output_section_id::DATA),
        SectionRule::exact_section(b"__nl_symbol_ptr", output_section_id::DATA),
        SectionRule::exact_section(b"__got", output_section_id::DATA),
        // TLS descriptors go in TDATA (after GOT), init data follows.
        // This separates TLS bind fixups from GOT bind fixups in the chain.
        // __thread_vars must NOT share the GOT output section — GOT-only entries
        // (e.g. for __eh_frame personality pointers) would overlap with TLV descriptors.
        // __thread_vars uses PREINIT_ARRAY (unused on Mach-O) as its dedicated
        // output section so all thread_vars from all objects are grouped contiguously.
        // Using DATA would interleave them with __data from other objects.
        SectionRule::exact_section(b"__thread_vars", output_section_id::PREINIT_ARRAY),
        SectionRule::exact_section(b"__thread_data", output_section_id::TDATA),
        SectionRule::exact_section(b"__thread_bss", output_section_id::TBSS),
        // Constructor/destructor function pointer arrays (Mach-O equivalent of
        // .init_array/.fini_array)
        SectionRule::exact_section(b"__mod_init_func", output_section_id::INIT_ARRAY),
        SectionRule::exact_section(b"__mod_term_func", output_section_id::FINI_ARRAY),
        SectionRule::exact_section(b"__gcc_except_tab", output_section_id::GCC_EXCEPT_TABLE),
        SectionRule::exact_section(b".rustc", output_section_id::DATA),
        SectionRule::exact_section(b"__bss", output_section_id::BSS),
        SectionRule::exact_section(b"__common", output_section_id::BSS),
        SectionRule::exact_section(b"__unwind_info", output_section_id::RODATA),
        SectionRule::exact_section(b"__eh_frame", output_section_id::EH_FRAME),
        SectionRule::exact_section(b"__compact_unwind", output_section_id::RODATA),
    ]
};

/// Trim trailing NUL bytes from a fixed-size Mach-O name field.
pub(crate) fn trim_nul(name: &[u8; 16]) -> &[u8] {
    let end = name.iter().position(|&b| b == 0).unwrap_or(16);
    // Safety: end <= 16, and the array has 16 elements
    &name.as_slice()[..end]
}

#[cfg(test)]
mod adrp_tests {
    use super::decode_adrp_target_page;

    /// Build an `ADRP Xd, <label>` instruction word. `imm21` is the
    /// 21-bit signed page-count offset; it's packed as
    /// `immhi:immlo` per the ARM ARM.
    fn encode_adrp(imm21: i32, rd: u32) -> u32 {
        assert!((-(1 << 20)..(1 << 20)).contains(&imm21));
        let imm21 = (imm21 as u32) & 0x1F_FFFF;
        let immlo = imm21 & 0x3;
        let immhi = (imm21 >> 2) & 0x7_FFFF;
        // bit 31 = 1 (op = ADRP), bits 28..24 = 0b10000 (0x10).
        0x9000_0000 | (immlo << 29) | (immhi << 5) | (rd & 0x1f)
    }

    #[test]
    fn zero_offset_targets_current_page() {
        let insn = encode_adrp(0, 0);
        assert_eq!(
            decode_adrp_target_page(insn, 0x1000_0000).unwrap(),
            0x1000_0000
        );
        // PC mid-page still rounds to the page.
        assert_eq!(
            decode_adrp_target_page(insn, 0x1000_0ABC).unwrap(),
            0x1000_0000
        );
    }

    #[test]
    fn positive_small_offset() {
        // adrp x0, <label at +1 page>
        let insn = encode_adrp(1, 0);
        assert_eq!(decode_adrp_target_page(insn, 0).unwrap(), 0x1000);
        assert_eq!(decode_adrp_target_page(insn, 0x2000).unwrap(), 0x3000);
    }

    #[test]
    fn negative_small_offset() {
        // adrp x0, <label at -1 page>
        let insn = encode_adrp(-1, 0);
        assert_eq!(decode_adrp_target_page(insn, 0x2000).unwrap(), 0x1000);
        assert_eq!(decode_adrp_target_page(insn, 0x1000).unwrap(), 0);
    }

    #[test]
    fn rd_field_doesnt_leak_into_immediate() {
        // Every Rd (0..=31) with the same offset must decode identically.
        let expected = decode_adrp_target_page(encode_adrp(42, 0), 0).unwrap();
        for rd in 0..32 {
            assert_eq!(
                decode_adrp_target_page(encode_adrp(42, rd), 0).unwrap(),
                expected,
                "rd={rd} changed decoded target"
            );
        }
    }

    #[test]
    fn maximum_positive_offset() {
        // imm21 max = 2^20 - 1 = 1048575 pages = 4 GiB - 4 KiB.
        let max = (1i32 << 20) - 1;
        let insn = encode_adrp(max, 0);
        let expected_delta = (max as u64) << 12;
        assert_eq!(decode_adrp_target_page(insn, 0).unwrap(), expected_delta,);
    }

    #[test]
    fn maximum_negative_offset() {
        // imm21 min = -2^20. At that range, PC = 4 GiB lands target at 0.
        let min = -(1i32 << 20);
        let insn = encode_adrp(min, 0);
        let pc = 1u64 << 32;
        let expected = pc.wrapping_add(((min as i64) << 12) as u64) & !0xFFF;
        assert_eq!(decode_adrp_target_page(insn, pc).unwrap(), expected);
    }

    #[test]
    fn rejects_adr_variant() {
        // ADR (op=0) has the same layout but bit 31 = 0. Our decoder
        // is page-only and deliberately refuses this variant so callers
        // don't mistake byte-offset ADR for an ADRP page.
        let adrp = encode_adrp(1, 0);
        let adr = adrp & !0x8000_0000; // clear bit 31
        assert!(decode_adrp_target_page(adr, 0).is_none());
    }

    #[test]
    fn rejects_non_adr_family_opcode() {
        // A BR / BLR / MOV instruction happens to have the op bit set
        // but different bits 24..28. Must return None.
        let bad = 0xD503_201F; // NOP
        assert!(decode_adrp_target_page(bad, 0).is_none());
    }

    #[test]
    fn pc_not_page_aligned_is_rounded_down() {
        let insn = encode_adrp(1, 0);
        // PC lands mid-page; source_page must be (PC & !0xFFF).
        assert_eq!(
            decode_adrp_target_page(insn, 0x1234).unwrap(),
            0x1000 + 0x1000
        );
        assert_eq!(decode_adrp_target_page(insn, 0x1FFF).unwrap(), 0x2000);
    }

    #[test]
    fn known_real_encoding_clang_emits() {
        // A clang-emitted `adrp x0, _sym@PAGE` where `_sym`'s page is
        // 1 page after the ADRP's page decodes to exactly that page.
        // This is the same encoding as `encode_adrp(1, 0)` but spelled
        // out as a literal to catch any bit-position regressions in the
        // encoder helper itself.
        let insn: u32 = 0x90000000 | (0u32 << 29) | (0u32 << 5) | 0 // imm21=0
            | (1u32 << 29); // immlo bit 0 set -> imm21 = 1
        assert_eq!(decode_adrp_target_page(insn, 0).unwrap(), 0x1000);
    }
}

#[cfg(test)]
mod pageoff12_tests {
    use super::decode_pageoff12_byte_offset;

    /// Encode `LDR Xt, [Xn, #imm]` — 64-bit load, size=11.
    fn encode_ldr_xt(imm12: u32, rn: u32, rt: u32) -> u32 {
        assert!(imm12 < 4096);
        // size=11, fixed 111001, opc=01, imm12, Rn, Rt.
        // 11_111_0_01_01_imm12_Rn_Rt
        0xF940_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
    }

    /// Encode `LDR Wt, [Xn, #imm]` — 32-bit load, size=10.
    fn encode_ldr_wt(imm12: u32, rn: u32, rt: u32) -> u32 {
        // size=10, opc=01.
        0xB940_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
    }

    /// Encode `LDRB Wt, [Xn, #imm]` — byte load, size=00.
    fn encode_ldrb(imm12: u32, rn: u32, rt: u32) -> u32 {
        0x3940_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
    }

    /// Encode `LDRH Wt, [Xn, #imm]` — halfword load, size=01.
    fn encode_ldrh(imm12: u32, rn: u32, rt: u32) -> u32 {
        0x7940_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F)
    }

    /// Encode `ADD Xd, Xn, #imm` — 64-bit, shift=0.
    fn encode_add_imm(imm12: u32, rn: u32, rd: u32) -> u32 {
        // sf=1, op=0, S=0, fixed 100010, shift=00, imm12, Rn, Rd.
        0x9100_0000 | ((imm12 & 0xFFF) << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F)
    }

    #[test]
    fn ldr_xt_scales_by_eight() {
        // `ldr x0, [x1, #0x40]` — imm12 = 8, byte offset = 0x40.
        let insn = encode_ldr_xt(8, 1, 0);
        assert_eq!(decode_pageoff12_byte_offset(insn), Some(0x40));
    }

    #[test]
    fn ldr_wt_scales_by_four() {
        let insn = encode_ldr_wt(8, 1, 0);
        assert_eq!(decode_pageoff12_byte_offset(insn), Some(0x20));
    }

    #[test]
    fn ldrh_scales_by_two() {
        let insn = encode_ldrh(8, 1, 0);
        assert_eq!(decode_pageoff12_byte_offset(insn), Some(0x10));
    }

    #[test]
    fn ldrb_no_scaling() {
        let insn = encode_ldrb(8, 1, 0);
        assert_eq!(decode_pageoff12_byte_offset(insn), Some(8));
    }

    #[test]
    fn add_imm_raw_bytes() {
        // `add x0, x1, #0x123` — imm12 = 0x123.
        let insn = encode_add_imm(0x123, 1, 0);
        assert_eq!(decode_pageoff12_byte_offset(insn), Some(0x123));
    }

    #[test]
    fn register_fields_dont_leak() {
        let expected = decode_pageoff12_byte_offset(encode_ldr_xt(5, 0, 0)).unwrap();
        for rn in 0..32 {
            for rt in 0..32 {
                assert_eq!(
                    decode_pageoff12_byte_offset(encode_ldr_xt(5, rn, rt)),
                    Some(expected),
                );
            }
        }
    }

    #[test]
    fn boundary_imm12_max() {
        // imm12 max = 4095. For LDR Xt, offset = 4095 * 8 = 32760.
        let insn = encode_ldr_xt(4095, 1, 0);
        assert_eq!(decode_pageoff12_byte_offset(insn), Some(4095 * 8));
    }

    #[test]
    fn add_with_shift_12_rejected() {
        // ADD with shift=01 (imm shifted left 12) is not a
        // PAGEOFF12 variant — it's for add-page-sized immediates
        // and can't carry a relocation we'd resolve here.
        let mut insn = encode_add_imm(1, 0, 0);
        insn |= 1 << 22; // set shift bit.
        assert!(decode_pageoff12_byte_offset(insn).is_none());
    }

    #[test]
    fn rejects_unrelated_instructions() {
        // NOP (0xD503201F) and a plain ADRP — neither is a
        // PAGEOFF12-carrying instruction.
        assert!(decode_pageoff12_byte_offset(0xD503_201F).is_none());
        assert!(decode_pageoff12_byte_offset(0x9000_0000).is_none());
    }

    #[test]
    fn clang_ldr_got_pattern_decodes() {
        // Typical clang text→GOT pattern:
        //   adrp x16, _sym@GOTPAGE
        //   ldr  x16, [x16, _sym@GOTPAGEOFF]
        // where `_sym@GOTPAGEOFF` resolves to the low 12 bits of the
        // GOT slot for `_sym`. At relocation time the imm12 in the
        // LDR holds the pre-relocation offset; assembler fills it
        // with the expected post-relocation offset. Here the
        // assembler emitted imm12=32, targeting offset 0x100 (= 32 *
        // 8) within the page.
        let insn = 0xF9400000 | (32u32 << 10) | (16u32 << 5) | 16;
        assert_eq!(decode_pageoff12_byte_offset(insn), Some(0x100));
    }
}
