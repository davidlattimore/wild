// Verify that _GLOBAL_OFFSET_TABLE_ is emitted as a local hidden symbol
// and that at least one GOT entry exists when building a shared object.
// The dynamic linker requires _GLOBAL_OFFSET_TABLE_ to not be exported.
//#Arch:aarch64
//#Mode:dynamic
//#ReferenceLinkers:lld
//#CompArgs:-fPIC
//#LinkArgs:-shared
//#DiffIgnore:.dynamic.DT_FLAGS_1*
//#DiffIgnore:section.got.plt.entsize
//#RunEnabled:false
//#ExpectSection:.got
//#ExpectSym:_GLOBAL_OFFSET_TABLE_ binding=local
//#NoDynSym:_GLOBAL_OFFSET_TABLE_
extern int foo;
// Reference _GLOBAL_OFFSET_TABLE_ explicitly to force it into symtab
extern char _GLOBAL_OFFSET_TABLE_[];
int bar(void) { return foo + (int)(long)_GLOBAL_OFFSET_TABLE_; }
