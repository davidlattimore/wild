//#Mode:dynamic
//#RunEnabled:false
//#LinkArgs:-shared -T ./linker-script-provide.ld
//#CompArgs:-fPIC
//#ExpectSym:provided_absolute address=0x1000
//#ExpectDynSym:provided_absolute address=0x1000
//#ExpectSym:provided_hidden_absolute address=0x2000
//#NoDynSym:provided_hidden_absolute
//#ExpectSym:__text_start
//#ExpectSym:__text_end
//#ExpectSym:__data_start
//#ExpectSym:__data_end
// GNU ld doesn't emit unreferenced `PROVIDE` symbols
//#NoSym:unreferenced_symbol
//#DiffIgnore:.dynamic.*
//#DiffIgnore:section.got
//#DiffIgnore:section.rela.dyn
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment
//#DiffIgnore:rel.extra-opt.R_X86_64_REX_GOTPCRELX.MovIndirectToLea.invalid-shared-object
//#DiffIgnore:rel.missing-got-dynamic.shared-object
//#DiffIgnore:rel.R_AARCH64_ADR_GOT_PAGE.R_AARCH64_ADR_GOT_PAGE
//#DiffIgnore:section.riscv.attributes
//#DiffIgnore:segment.RISCV_ATTRIBUTES.*
// GNU ld behaves strangely when a symbol referenced in a linker script is
// empty. See this:
// https://github.com/davidlattimore/wild/pull/1525#discussion_r2785478582
//#DiffIgnore:dynsym.__data_start.section
//#DiffIgnore:dynsym.__data_end.section

extern char provided_absolute __attribute__((weak));
extern char provided_hidden_absolute __attribute__((weak));
extern char __text_start __attribute__((weak));
extern char __text_end __attribute__((weak));
extern char __data_start __attribute__((weak));
extern char __data_end __attribute__((weak));

void* get_provided(void) {
  return &provided_absolute + (long)&provided_hidden_absolute;
}

unsigned long get_text_size(void) {
  return (unsigned long)&__text_end - (unsigned long)&__text_start;
}

unsigned long get_data_size(void) {
  return (unsigned long)&__data_end - (unsigned long)&__data_start;
}
