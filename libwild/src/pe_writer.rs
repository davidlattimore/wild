//! PE executable output: layout computation and writing.
//!
//! This module handles the PE-specific portion of linking: computing section layout,
//! writing PE headers, copying section data, and applying COFF relocations.

use crate::args::Args;
use crate::args::windows::PeArgs;
use crate::arch::Architecture;
use crate::coff::CoffObjectFile;
use crate::error::Context as _;
use crate::error::Result;
use crate::platform::ObjectFile;
use crate::platform::Symbol as _;
use crate::resolution::ResolvedFile;
use crate::resolution::ResolvedGroup;
use crate::resolution::SectionSlot;
use crate::sharding::ShardKey as _;
use crate::symbol::UnversionedSymbolName;
use crate::symbol_db::SymbolDb;
use object::LittleEndian as LE;
use object::pe;
use std::collections::HashMap;

// ── Constants ────────────────────────────────────────────────────────────────

const IMAGE_BASE_X64: u64 = 0x0000_0001_4000_0000;
const SECTION_ALIGNMENT: u32 = 0x1000;
const FILE_ALIGNMENT: u32 = 0x200;

const DOS_HEADER_SIZE: u32 = core::mem::size_of::<pe::ImageDosHeader>() as u32;
const PE_SIGNATURE_SIZE: u32 = 4;
const COFF_HEADER_SIZE: u32 = core::mem::size_of::<pe::ImageFileHeader>() as u32;
const OPTIONAL_HEADER_BASE_SIZE: u32 = core::mem::size_of::<pe::ImageOptionalHeader64>() as u32;
const DATA_DIRS_SIZE: u32 =
    (pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) * core::mem::size_of::<pe::ImageDataDirectory>() as u32;
const OPTIONAL_HEADER_SIZE: u32 = OPTIONAL_HEADER_BASE_SIZE + DATA_DIRS_SIZE;
const SECTION_HEADER_SIZE: u32 = core::mem::size_of::<pe::ImageSectionHeader>() as u32;

// ── Layout data structures ───────────────────────────────────────────────────

pub(crate) struct PeLayout<'data> {
    pub(crate) args: &'data Args<PeArgs>,
    pub(crate) image_base: u64,
    pub(crate) sections: Vec<PeOutputSection<'data>>,
    pub(crate) entry_point_rva: u32,
    pub(crate) size_of_headers: u32,
    pub(crate) size_of_image: u32,
    pub(crate) machine: u16,
    pub(crate) file_size: u64,
    pub(crate) symbol_addresses: Vec<u64>,
}

pub(crate) struct PeOutputSection<'data> {
    pub(crate) name: [u8; 8],
    pub(crate) virtual_address: u32,
    pub(crate) virtual_size: u32,
    pub(crate) file_offset: u32,
    pub(crate) raw_data_size: u32,
    pub(crate) characteristics: u32,
    pub(crate) contributions: Vec<SectionContribution<'data>>,
    pub(crate) is_bss: bool,
}

pub(crate) struct SectionContribution<'data> {
    pub(crate) object: &'data CoffObjectFile<'data>,
    pub(crate) input_section_index: object::SectionIndex,
    pub(crate) output_offset: u32,
    pub(crate) size: u32,
    pub(crate) symbol_id_start: crate::symbol_db::SymbolId,
}

// ── Section name / characteristics mapping ───────────────────────────────────

fn output_section_name(input_name: &[u8]) -> [u8; 8] {
    let base_name = if let Some(dollar_pos) = input_name.iter().position(|&b| b == b'$') {
        &input_name[..dollar_pos]
    } else {
        input_name
    };

    match base_name {
        b".text" => *b".text\0\0\0",
        b".rdata" => *b".rdata\0\0",
        b".data" => *b".data\0\0\0",
        b".bss" => *b".bss\0\0\0\0",
        b".pdata" => *b".pdata\0\0",
        b".xdata" => *b".xdata\0\0",
        _ => {
            let mut out = [0u8; 8];
            let len = base_name.len().min(8);
            out[..len].copy_from_slice(&base_name[..len]);
            out
        }
    }
}

fn merge_characteristics(chars: u32) -> u32 {
    chars
        & (pe::IMAGE_SCN_CNT_CODE
            | pe::IMAGE_SCN_CNT_INITIALIZED_DATA
            | pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA
            | pe::IMAGE_SCN_MEM_EXECUTE
            | pe::IMAGE_SCN_MEM_READ
            | pe::IMAGE_SCN_MEM_WRITE)
}

fn coff_section_alignment(chars: u32) -> u32 {
    let align_field = (chars >> 20) & 0xF;
    if align_field == 0 {
        1
    } else {
        1 << (align_field - 1)
    }
}

// ── Layout computation ───────────────────────────────────────────────────────

pub(crate) fn compute_layout<'data>(
    symbol_db: &SymbolDb<'data, CoffObjectFile<'data>>,
    resolved_groups: &[ResolvedGroup<'data, CoffObjectFile<'data>>],
    args: &'data Args<PeArgs>,
) -> Result<PeLayout<'data>> {
    let image_base = IMAGE_BASE_X64;
    let machine = match args.arch {
        Architecture::X86_64 => pe::IMAGE_FILE_MACHINE_AMD64,
        Architecture::AArch64 => pe::IMAGE_FILE_MACHINE_ARM64,
        _ => crate::bail!("Unsupported PE architecture: {:?}", args.arch),
    };

    // Step 1: Collect input sections into output sections.
    let mut output_sections: Vec<PeOutputSection<'data>> = Vec::new();
    let mut section_map: HashMap<([u8; 8], u32), usize> = HashMap::new();

    for group in resolved_groups {
        for file in &group.files {
            let ResolvedFile::Object(resolved_obj) = file else {
                continue;
            };
            let object = resolved_obj.common.object;
            let symbol_id_start = resolved_obj.common.symbol_id_range.start();

            for (slot_index, slot) in resolved_obj.sections.iter().enumerate() {
                match slot {
                    SectionSlot::Discard => continue,
                    SectionSlot::Loaded(_)
                    | SectionSlot::Unloaded(_)
                    | SectionSlot::MustLoad(_) => {}
                    _ => continue,
                }

                let section_index = object::SectionIndex(slot_index + 1);
                let section_header = object.section(section_index)?;
                let name_bytes = object.section_name(section_header)?;
                let out_name = output_section_name(name_bytes);
                let in_chars = section_header.characteristics.get(LE);
                let out_chars = merge_characteristics(in_chars);
                let is_bss = in_chars & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0;

                let size = section_header.size_of_raw_data.get(LE);
                if size == 0 {
                    continue;
                }

                let section_idx = *section_map
                    .entry((out_name, out_chars))
                    .or_insert_with(|| {
                        output_sections.push(PeOutputSection {
                            name: out_name,
                            virtual_address: 0,
                            virtual_size: 0,
                            file_offset: 0,
                            raw_data_size: 0,
                            characteristics: out_chars,
                            contributions: Vec::new(),
                            is_bss,
                        });
                        output_sections.len() - 1
                    });

                let out_section = &mut output_sections[section_idx];

                let input_alignment = coff_section_alignment(in_chars).max(1);
                let aligned_offset = align_up(out_section.virtual_size, input_alignment);

                out_section.contributions.push(SectionContribution {
                    object,
                    input_section_index: section_index,
                    output_offset: aligned_offset,
                    size,
                    symbol_id_start,
                });

                out_section.virtual_size = aligned_offset + size;
                if !is_bss {
                    out_section.raw_data_size = aligned_offset + size;
                }
            }
        }
    }

    output_sections.sort_by_key(|s| section_sort_key(&s.name));

    // Step 2: Compute header size
    let headers_raw = DOS_HEADER_SIZE
        + PE_SIGNATURE_SIZE
        + COFF_HEADER_SIZE
        + OPTIONAL_HEADER_SIZE
        + SECTION_HEADER_SIZE * output_sections.len() as u32;
    let size_of_headers = align_up(headers_raw, FILE_ALIGNMENT);

    // Step 3: Assign virtual addresses and file offsets
    let mut next_rva = align_up(size_of_headers, SECTION_ALIGNMENT);
    let mut next_file_offset = size_of_headers;

    for section in &mut output_sections {
        section.virtual_address = next_rva;
        section.file_offset = if section.is_bss { 0 } else { next_file_offset };

        if !section.is_bss {
            section.raw_data_size = align_up(section.raw_data_size, FILE_ALIGNMENT);
            next_file_offset += section.raw_data_size;
        }

        next_rva = align_up(next_rva + section.virtual_size, SECTION_ALIGNMENT);
    }

    let size_of_image = next_rva;
    let file_size = next_file_offset as u64;

    // Step 4: Compute symbol addresses
    let mut section_address_map: HashMap<(usize, usize), (u32, u32)> = HashMap::new();
    for section in &output_sections {
        for contrib in &section.contributions {
            let key = (
                contrib.object as *const _ as usize,
                contrib.input_section_index.0,
            );
            section_address_map.insert(key, (section.virtual_address, contrib.output_offset));
        }
    }

    let num_symbols = symbol_db.num_symbols();
    let mut symbol_addresses = vec![0u64; num_symbols];

    for group in resolved_groups {
        for file in &group.files {
            let ResolvedFile::Object(resolved_obj) = file else {
                continue;
            };
            let object = resolved_obj.common.object;
            let symbol_id_range = &resolved_obj.common.symbol_id_range;
            let obj_ptr = object as *const _ as usize;

            for (local_sym_index, symbol) in object.enumerate_symbols() {
                let global_id = symbol_id_range.offset_to_id(local_sym_index.0);
                let global_index = global_id.as_usize();
                if global_index >= num_symbols {
                    continue;
                }

                let def_id = symbol_db.definition(global_id);
                if def_id != global_id {
                    continue;
                }

                if let Ok(Some(section_index)) =
                    object.symbol_section(symbol, local_sym_index)
                {
                    let key = (obj_ptr, section_index.0);
                    if let Some(&(section_va, contrib_offset)) = section_address_map.get(&key) {
                        let sym_value = symbol.value();
                        symbol_addresses[global_index] =
                            image_base + section_va as u64 + contrib_offset as u64 + sym_value;
                    }
                }
            }
        }
    }

    // Propagate addresses for redirected symbols
    for sym_id_raw in 0..num_symbols {
        let sym_id = crate::symbol_db::SymbolId::from_usize(sym_id_raw);
        let def_id = symbol_db.definition(sym_id);
        if def_id != sym_id && def_id.as_usize() < num_symbols {
            symbol_addresses[sym_id_raw] = symbol_addresses[def_id.as_usize()];
        }
    }

    // Step 5: Find entry point
    let entry_point_rva = if let Some(entry_name) = &args.entry {
        find_entry_point_rva(symbol_db, &symbol_addresses, entry_name, image_base)?
    } else {
        find_entry_point_rva(symbol_db, &symbol_addresses, "mainCRTStartup", image_base)
            .or_else(|_| {
                find_entry_point_rva(symbol_db, &symbol_addresses, "_mainCRTStartup", image_base)
            })
            .or_else(|_| {
                find_entry_point_rva(
                    symbol_db,
                    &symbol_addresses,
                    "WinMainCRTStartup",
                    image_base,
                )
            })
            .unwrap_or(0)
    };

    Ok(PeLayout {
        args,
        image_base,
        sections: output_sections,
        entry_point_rva,
        size_of_headers,
        size_of_image,
        machine,
        file_size,
        symbol_addresses,
    })
}

fn find_entry_point_rva<'data>(
    symbol_db: &SymbolDb<'data, CoffObjectFile<'data>>,
    symbol_addresses: &[u64],
    name: &str,
    image_base: u64,
) -> Result<u32> {
    let prehashed = UnversionedSymbolName::prehashed(name.as_bytes());
    let sym_id = symbol_db
        .get_unversioned(&prehashed)
        .with_context(|| format!("Entry point symbol `{name}` not found"))?;
    let def_id = symbol_db.definition(sym_id);
    let addr = symbol_addresses[def_id.as_usize()];
    if addr == 0 {
        crate::bail!("Entry point symbol `{name}` has no address");
    }
    Ok((addr - image_base) as u32)
}

fn section_sort_key(name: &[u8; 8]) -> u32 {
    match name {
        b".text\0\0\0" => 0,
        b".rdata\0\0" => 1,
        b".data\0\0\0" => 2,
        b".pdata\0\0" => 3,
        b".xdata\0\0" => 4,
        b".bss\0\0\0\0" => 5,
        _ => 10,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub(crate) fn link<'data>(
    symbol_db: &SymbolDb<'data, CoffObjectFile<'data>>,
    resolved_groups: &[ResolvedGroup<'data, CoffObjectFile<'data>>],
    args: &'data Args<PeArgs>,
    _output_kind: crate::OutputKind,
) -> Result {
    let pe_layout = compute_layout(symbol_db, resolved_groups, args)?;

    // Create the output file and write the PE image.
    let file_size = pe_layout.file_size;
    let mut buf = vec![0u8; file_size as usize];
    write_headers(&mut buf, &pe_layout)?;
    write_sections(&mut buf, &pe_layout)?;

    std::fs::write(&args.output, &buf)
        .with_context(|| format!("Failed to write PE output to `{}`", args.output.display()))?;

    Ok(())
}

// ── Writing ──────────────────────────────────────────────────────────────────

fn write_headers(buf: &mut [u8], layout: &PeLayout) -> Result {
    let e = LE;
    let mut offset = 0usize;

    // DOS Header
    let dos_header: &mut pe::ImageDosHeader = from_bytes_mut_at(buf, &mut offset)?;
    dos_header.e_magic.set(e, pe::IMAGE_DOS_SIGNATURE);
    dos_header.e_lfanew.set(e, DOS_HEADER_SIZE);

    // PE Signature
    let sig = buf
        .get_mut(offset..offset + 4)
        .context("Buffer too small for PE signature")?;
    sig.copy_from_slice(&pe::IMAGE_NT_SIGNATURE.to_le_bytes());
    offset += 4;

    // COFF File Header
    let file_header: &mut pe::ImageFileHeader = from_bytes_mut_at(buf, &mut offset)?;
    file_header.machine.set(e, layout.machine);
    file_header
        .number_of_sections
        .set(e, layout.sections.len() as u16);
    file_header.time_date_stamp.set(e, 0);
    file_header.pointer_to_symbol_table.set(e, 0);
    file_header.number_of_symbols.set(e, 0);
    file_header
        .size_of_optional_header
        .set(e, OPTIONAL_HEADER_SIZE as u16);
    file_header.characteristics.set(
        e,
        pe::IMAGE_FILE_EXECUTABLE_IMAGE | pe::IMAGE_FILE_LARGE_ADDRESS_AWARE,
    );

    // Optional Header (PE32+)
    let opt_header: &mut pe::ImageOptionalHeader64 = from_bytes_mut_at(buf, &mut offset)?;
    opt_header.magic.set(e, pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    opt_header.major_linker_version = 1;
    opt_header.minor_linker_version = 0;
    opt_header
        .address_of_entry_point
        .set(e, layout.entry_point_rva);
    opt_header.image_base.set(e, layout.image_base);
    opt_header.section_alignment.set(e, SECTION_ALIGNMENT);
    opt_header.file_alignment.set(e, FILE_ALIGNMENT);
    opt_header.major_operating_system_version.set(e, 6);
    opt_header.minor_operating_system_version.set(e, 0);
    opt_header.major_subsystem_version.set(e, 6);
    opt_header.minor_subsystem_version.set(e, 0);
    opt_header.size_of_image.set(e, layout.size_of_image);
    opt_header.size_of_headers.set(e, layout.size_of_headers);
    opt_header.subsystem.set(e, pe::IMAGE_SUBSYSTEM_WINDOWS_CUI);
    opt_header.dll_characteristics.set(
        e,
        pe::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            | pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            | pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | pe::IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
    );
    opt_header.size_of_stack_reserve.set(e, 0x100000);
    opt_header.size_of_stack_commit.set(e, 0x1000);
    opt_header.size_of_heap_reserve.set(e, 0x100000);
    opt_header.size_of_heap_commit.set(e, 0x1000);
    opt_header
        .number_of_rva_and_sizes
        .set(e, pe::IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32);

    // Compute aggregate sizes for the optional header
    let mut size_of_code = 0u32;
    let mut size_of_initialized_data = 0u32;
    let mut size_of_uninitialized_data = 0u32;
    let mut base_of_code = 0u32;
    for section in &layout.sections {
        if section.characteristics & pe::IMAGE_SCN_CNT_CODE != 0 {
            size_of_code += section.raw_data_size;
            if base_of_code == 0 {
                base_of_code = section.virtual_address;
            }
        }
        if section.characteristics & pe::IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
            size_of_initialized_data += section.raw_data_size;
        }
        if section.characteristics & pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
            size_of_uninitialized_data += section.virtual_size;
        }
    }
    opt_header.size_of_code.set(e, size_of_code);
    opt_header
        .size_of_initialized_data
        .set(e, size_of_initialized_data);
    opt_header
        .size_of_uninitialized_data
        .set(e, size_of_uninitialized_data);
    opt_header.base_of_code.set(e, base_of_code);

    // Data directories (16 entries, all zeroed for now)
    let data_dirs_slice = buf
        .get_mut(offset..offset + DATA_DIRS_SIZE as usize)
        .context("Buffer too small for data directories")?;
    data_dirs_slice.fill(0);
    offset += DATA_DIRS_SIZE as usize;

    // Section Headers
    for section in &layout.sections {
        let sec_header: &mut pe::ImageSectionHeader = from_bytes_mut_at(buf, &mut offset)?;
        sec_header.name = section.name;
        sec_header.virtual_size.set(e, section.virtual_size);
        sec_header.virtual_address.set(e, section.virtual_address);
        sec_header.size_of_raw_data.set(
            e,
            if section.is_bss {
                0
            } else {
                section.raw_data_size
            },
        );
        sec_header.pointer_to_raw_data.set(e, section.file_offset);
        sec_header.characteristics.set(e, section.characteristics);
    }

    Ok(())
}

fn write_sections(buf: &mut [u8], layout: &PeLayout) -> Result {
    for (section_idx, section) in layout.sections.iter().enumerate() {
        if section.is_bss {
            continue;
        }

        for contrib in &section.contributions {
            let section_header = contrib.object.section(contrib.input_section_index)?;
            let data = contrib.object.raw_section_data(section_header)?;
            let out_offset = section.file_offset as usize + contrib.output_offset as usize;
            let copy_size = data.len().min(contrib.size as usize);
            let out_end = out_offset + copy_size;

            if out_end > buf.len() {
                crate::bail!(
                    "Section data write out of bounds: offset={out_offset}, size={copy_size}, buf_len={}",
                    buf.len()
                );
            }

            buf[out_offset..out_end].copy_from_slice(&data[..copy_size]);

            apply_relocations(buf, layout, section, section_idx, contrib)?;
        }
    }

    Ok(())
}

fn apply_relocations(
    buf: &mut [u8],
    layout: &PeLayout,
    section: &PeOutputSection,
    section_idx: usize,
    contrib: &SectionContribution,
) -> Result {
    let relocations = contrib
        .object
        .relocations(contrib.input_section_index, &())?;

    for reloc in relocations {
        let reloc_type = reloc.typ.get(LE);
        let reloc_offset_in_section = reloc.virtual_address.get(LE);
        let symbol_table_index = reloc.symbol_table_index.get(LE) as usize;

        let global_id = contrib.symbol_id_start.add_usize(symbol_table_index);
        let target_addr = layout.symbol_addresses[global_id.as_usize()];

        let file_offset = section.file_offset as usize
            + contrib.output_offset as usize
            + reloc_offset_in_section as usize;

        let reloc_va = layout.image_base
            + section.virtual_address as u64
            + contrib.output_offset as u64
            + reloc_offset_in_section as u64;

        match reloc_type {
            pe::IMAGE_REL_AMD64_ABSOLUTE => {}
            pe::IMAGE_REL_AMD64_ADDR64 => {
                write_u64(buf, file_offset, target_addr)?;
            }
            pe::IMAGE_REL_AMD64_ADDR32 => {
                write_u32(buf, file_offset, target_addr as u32)?;
            }
            pe::IMAGE_REL_AMD64_ADDR32NB => {
                let rva = target_addr.wrapping_sub(layout.image_base);
                write_u32(buf, file_offset, rva as u32)?;
            }
            pe::IMAGE_REL_AMD64_REL32 => {
                let value = target_addr.wrapping_sub(reloc_va).wrapping_sub(4);
                write_i32(buf, file_offset, value as i32)?;
            }
            pe::IMAGE_REL_AMD64_REL32_1 => {
                let value = target_addr.wrapping_sub(reloc_va).wrapping_sub(5);
                write_i32(buf, file_offset, value as i32)?;
            }
            pe::IMAGE_REL_AMD64_REL32_2 => {
                let value = target_addr.wrapping_sub(reloc_va).wrapping_sub(6);
                write_i32(buf, file_offset, value as i32)?;
            }
            pe::IMAGE_REL_AMD64_REL32_3 => {
                let value = target_addr.wrapping_sub(reloc_va).wrapping_sub(7);
                write_i32(buf, file_offset, value as i32)?;
            }
            pe::IMAGE_REL_AMD64_REL32_4 => {
                let value = target_addr.wrapping_sub(reloc_va).wrapping_sub(8);
                write_i32(buf, file_offset, value as i32)?;
            }
            pe::IMAGE_REL_AMD64_REL32_5 => {
                let value = target_addr.wrapping_sub(reloc_va).wrapping_sub(9);
                write_i32(buf, file_offset, value as i32)?;
            }
            pe::IMAGE_REL_AMD64_SECTION => {
                write_u16(buf, file_offset, (section_idx + 1) as u16)?;
            }
            pe::IMAGE_REL_AMD64_SECREL => {
                let section_base = layout.image_base + section.virtual_address as u64;
                let secrel = target_addr.wrapping_sub(section_base);
                write_u32(buf, file_offset, secrel as u32)?;
            }
            _ => {
                crate::bail!(
                    "Unsupported COFF relocation type 0x{reloc_type:04x} at offset 0x{file_offset:x}"
                );
            }
        }
    }

    Ok(())
}

// ── Helper functions ─────────────────────────────────────────────────────────

fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

fn from_bytes_mut_at<'a, T: object::pod::Pod>(buf: &'a mut [u8], offset: &mut usize) -> Result<&'a mut T> {
    let size = core::mem::size_of::<T>();
    let end = *offset + size;
    if end > buf.len() {
        crate::bail!("Buffer too small: need {end} bytes, have {}", buf.len());
    }
    let slice = &mut buf[*offset..end];
    let ptr = slice.as_mut_ptr() as *mut T;
    *offset = end;
    Ok(unsafe { &mut *ptr })
}

fn write_u16(buf: &mut [u8], offset: usize, value: u16) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 2)
        .context("Relocation write out of bounds (u16)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 4)
        .context("Relocation write out of bounds (u32)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_i32(buf: &mut [u8], offset: usize, value: i32) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 4)
        .context("Relocation write out of bounds (i32)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_u64(buf: &mut [u8], offset: usize, value: u64) -> Result {
    let bytes = buf
        .get_mut(offset..offset + 8)
        .context("Relocation write out of bounds (u64)")?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}
