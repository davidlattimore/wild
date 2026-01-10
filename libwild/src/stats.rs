struct Stats {
    num_objects: usize,
    num_symbols: usize,
    num_section_ids: usize,
}

pub(crate) fn print_stats(layout: &crate::layout::Layout) {
    println!("{}", Stats::new(layout));
}

impl Stats {
    fn new(layout: &crate::layout::Layout) -> Self {
        Self {
            num_objects: layout.symbol_db.num_objects(),
            num_symbols: layout.symbol_db.num_symbols(),
            num_section_ids: layout.output_sections.num_sections(),
        }
    }
}

impl std::fmt::Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Num objects: {}", self.num_objects)?;
        writeln!(f, "Num symbols: {}", self.num_symbols)?;
        writeln!(f, "Num section IDs: {}", self.num_section_ids)?;
        Ok(())
    }
}
