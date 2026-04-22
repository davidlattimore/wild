//#LinkerDriver:clang
//#RustFlags:-Cstrip=debuginfo

// Regression guard for cargo's default release profile, which sets
// `strip = "debuginfo"`. Historically wild tripped `strip` twice:
//   1. Missing INDIRECT_SYMBOL_LOCAL (0x80000000) on locally-defined
//      indirect-table entries — `strip` refused with "symbols
//      referenced by indirect symbol table entries that can't be
//      stripped".
//   2. `__literal8` output was stamped S_NON_LAZY_SYMBOL_POINTERS
//      (0x06) with `reserved1 = 0`, overlapping the __stubs/__got
//      indirect-table ranges — `strip` rewrote entries past
//      end-of-symtab and the stripped binary SIGSEGV'd at first
//      pthread call.
// Both are fixed in the Mach-O section-header emission pipeline
// (`macho_writer::macho_section_info` + `__literal*` now folds into
// `__TEXT,__const` at `ld.cpp:213` parity). A successful run
// produces exit 42; a regression produces exit 139 (SIGSEGV) or
// a non-zero `strip` exit from the linker driver.
fn main() {
    std::process::exit(42);
}
