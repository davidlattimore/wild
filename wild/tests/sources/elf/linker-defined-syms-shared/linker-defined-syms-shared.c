// Test that linker-defined section boundary symbols are not exported to .dynsym
// in shared objects, matching GNU ld behavior.
// TODO: Once linker-defined symbol GC is implemented, add a variant that
// references these symbols and asserts they appear as GLOBAL in .dynsym.
//#LinkArgs:-shared -z now
//#RunEnabled:false
//#CompArgs:-fPIC
//#DiffEnabled:false

// These symbols should NOT appear in .dynsym for shared objects
//#NoDynSym:etext
//#NoDynSym:_etext
//#NoDynSym:__etext
//#NoDynSym:end
//#NoDynSym:_end
//#NoDynSym:edata
//#NoDynSym:_edata

// Wild keeps them in .symtab as LOCAL. GNU ld removes them entirely with
// --gc-sections, so we only assert this for Wild.
//#SkipLinker:ld
//#ExpectSym:etext binding=local
//#ExpectSym:_etext binding=local
//#ExpectSym:__etext binding=local
//#ExpectSym:end binding=local
//#ExpectSym:_end binding=local
//#ExpectSym:edata binding=local
//#ExpectSym:_edata binding=local

// data_var and bss_var ensure .data and .bss sections exist so that
// edata, _edata, end and _end symbols are emitted by Wild.
int data_var = 1;
int bss_var;

void foo(void) {}
