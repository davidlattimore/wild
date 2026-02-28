use hashbrown::HashMap;

pub(crate) fn hash_symbol_name(name: &[u8]) -> u32 {
    let mut r: u32 = 0;
    for &c in name {
        r = r
            .wrapping_mul(67)
            .wrapping_add(u32::from(c))
            .wrapping_sub(113);
    }
    r
}

pub(crate) fn compute_hash_table_slots(num_symbols: usize) -> usize {
    if num_symbols == 0 {
        return 0;
    }
    let min_slots = num_symbols * 4 / 3 + 1;
    let mut slots = 4usize;
    while slots < min_slots {
        slots *= 2;
    }
    slots
}

pub(crate) fn attrs_to_cu_entry(attrs: u8, cu_index: u32) -> u32 {
    let kind = u32::from((attrs >> 4) & 0x7);
    let is_static: u32 = if (attrs >> 7) != 0 { 1 } else { 0 };
    (cu_index & 0x00FF_FFFF) | (kind << 28) | (is_static << 31)
}

pub(crate) struct PubnamesIter<'a> {
    data: &'a [u8],
    pos: usize,
    set_end: usize,
}

impl<'a> PubnamesIter<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        let mut iter = Self {
            data,
            pos: 0,
            set_end: 0,
        };
        iter.begin_next_set();
        iter
    }

    fn begin_next_set(&mut self) -> bool {
        if self.pos + 4 > self.data.len() {
            return false;
        }
        let unit_length =
            u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap()) as usize;
        self.set_end = self.pos + 4 + unit_length;
        if self.set_end > self.data.len() {
            return false;
        }
        if unit_length < 10 {
            return false;
        }
        self.pos += 14;
        true
    }
}

impl<'a> Iterator for PubnamesIter<'a> {
    type Item = (&'a [u8], u8);

    fn next(&mut self) -> Option<(&'a [u8], u8)> {
        loop {
            if self.pos + 4 > self.set_end || self.pos + 4 > self.data.len() {
                self.pos = self.set_end;
                if !self.begin_next_set() {
                    return None;
                }
                continue;
            }

            let die_offset =
                u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 4;

            if die_offset == 0 {
                self.pos = self.set_end;
                if !self.begin_next_set() {
                    return None;
                }
                continue;
            }

            if self.pos >= self.set_end || self.pos >= self.data.len() {
                return None;
            }
            let attrs = self.data[self.pos];
            self.pos += 1;

            let name_start = self.pos;
            while self.pos < self.set_end && self.pos < self.data.len() && self.data[self.pos] != 0
            {
                self.pos += 1;
            }
            let name = &self.data[name_start..self.pos];
            if self.pos < self.data.len() && self.pos < self.set_end {
                self.pos += 1;
            }

            if !name.is_empty() {
                return Some((name, attrs));
            }
        }
    }
}

pub(crate) fn compute_symbol_table_size<'a>(
    sections: impl Iterator<Item = (Option<&'a [u8]>, Option<&'a [u8]>)>,
) -> usize {
    // Count how many times each name appears across all CUs.
    let mut name_ref_counts: HashMap<&'a [u8], usize> = HashMap::new();

    for (pubnames, pubtypes) in sections {
        for data in pubnames.into_iter().chain(pubtypes.into_iter()) {
            for (name, _attrs) in PubnamesIter::new(data) {
                *name_ref_counts.entry(name).or_insert(0) += 1;
            }
        }
    }

    if name_ref_counts.is_empty() {
        return 0;
    }

    let num_symbols = name_ref_counts.len();
    let hash_table_slots = compute_hash_table_slots(num_symbols);
    let symbol_table_bytes = hash_table_slots * 8;
    let cu_vectors_bytes: usize = name_ref_counts.values().map(|&count| 4 + count * 4).sum();
    let names_bytes: usize = name_ref_counts.keys().map(|n| n.len() + 1).sum();

    symbol_table_bytes + cu_vectors_bytes + 1 + names_bytes
}

pub(crate) fn write_symbol_table<'a>(
    sections: impl Iterator<Item = (Option<&'a [u8]>, Option<&'a [u8]>, u32)>,
    buf: &mut [u8],
) {
    let mut name_entries: HashMap<Vec<u8>, Vec<u32>> = HashMap::new();

    for (pubnames, pubtypes, cu_index) in sections {
        for data in pubnames.into_iter().chain(pubtypes.into_iter()) {
            for (name, attrs) in PubnamesIter::new(data) {
                let cu_entry = attrs_to_cu_entry(attrs, cu_index);
                name_entries
                    .entry(name.to_vec())
                    .or_default()
                    .push(cu_entry);
            }
        }
    }

    if name_entries.is_empty() {
        return;
    }

    let mut sorted_names: Vec<&Vec<u8>> = name_entries.keys().collect();
    sorted_names.sort();

    let num_symbols = sorted_names.len();
    let hash_table_slots = compute_hash_table_slots(num_symbols);
    let symbol_table_bytes = hash_table_slots * 8;

    let mut cu_vec_offsets: Vec<u32> = Vec::with_capacity(num_symbols);
    let mut cu_vec_pos: usize = 0;
    for name in &sorted_names {
        cu_vec_offsets.push(cu_vec_pos as u32);
        cu_vec_pos += 4 + name_entries[name.as_slice()].len() * 4;
    }

    let sentinel_offset = cu_vec_pos;

    let mut name_offsets: Vec<u32> = Vec::with_capacity(num_symbols);
    let mut name_pos: usize = sentinel_offset + 1;
    for name in &sorted_names {
        name_offsets.push(name_pos as u32);
        name_pos += name.len() + 1;
    }

    let cp = &mut buf[symbol_table_bytes..];

    for (i, name) in sorted_names.iter().enumerate() {
        let cv_off = cu_vec_offsets[i] as usize;
        let entries = &name_entries[name.as_slice()];
        let count = entries.len() as u32;
        cp[cv_off..cv_off + 4].copy_from_slice(&count.to_le_bytes());
        for (j, &entry) in entries.iter().enumerate() {
            let off = cv_off + 4 + j * 4;
            cp[off..off + 4].copy_from_slice(&entry.to_le_bytes());
        }
    }

    cp[sentinel_offset] = 0;

    for (i, name) in sorted_names.iter().enumerate() {
        let n_off = name_offsets[i] as usize;
        cp[n_off..n_off + name.len()].copy_from_slice(name);
        cp[n_off + name.len()] = 0;
    }

    let ht = &mut buf[0..symbol_table_bytes];
    for (i, name) in sorted_names.iter().enumerate() {
        let hash = hash_symbol_name(name);
        let mut slot = (hash as usize) % hash_table_slots;
        loop {
            let slot_off = slot * 8;
            let existing_name_off =
                u32::from_le_bytes(ht[slot_off..slot_off + 4].try_into().unwrap());
            let existing_cv_off =
                u32::from_le_bytes(ht[slot_off + 4..slot_off + 8].try_into().unwrap());
            if existing_name_off == 0 && existing_cv_off == 0 {
                ht[slot_off..slot_off + 4].copy_from_slice(&name_offsets[i].to_le_bytes());
                ht[slot_off + 4..slot_off + 8].copy_from_slice(&cu_vec_offsets[i].to_le_bytes());
                break;
            }
            slot = (slot + 1) % hash_table_slots;
        }
    }
}
