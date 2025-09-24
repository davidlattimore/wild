// Adding shared libraries should result in dynamic executables when
// unspecified: #836
//#Config:shared-input
//#LinkArgs:-z now --export-dynamic
//#ExpectDynSym:foo
//#Shared:empty.c
//#Mode:unspecified
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
// TODO: Wild probably should set dynamic linker here
//#EnableLinker:lld
//#RunEnabled:false

// Do not export symbols for static executables: #836
//#Config:static-exe
//#Mode:static
//#LinkArgs:-z now --export-dynamic
//#RunEnabled:false
//#DoesNotContain:.dynamic

//#Config:select-symbols
//#LinkArgs:-z now --export-dynamic-symbol bar --export-dynamic-symbol=baz
//#ExpectDynSym:bar
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:dynamic
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#EnableLinker:lld

//#Config:select-symbols-list
//#LinkArgs:-z now --export-dynamic-symbol-list ./export-dynamic.def
//#ExpectDynSym:foo
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:dynamic
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#EnableLinker:lld

//#Config:dynamic-symbols-list
//#LinkArgs:-z now -shared --dynamic-list ./export-dynamic.def
//#ExpectDynSym:foo
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:dynamic
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:file-header.entry
//#EnableLinker:lld

void foo(void) {};
void bar(void) {};
void baz(void) {};

void _start() { foo(); }
