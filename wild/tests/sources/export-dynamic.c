// clang-format off
// Adding shared libraries should yield dynamic executables: #836
//#Config:shared-input
//#LinkArgs:-z now --export-dynamic
//#ExpectDynSym:foo
//#Shared:empty.c
//#Mode:unspecified
//#Cross:false
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
// TODO: Wild probably should set dynamic linker here
//#DiffIgnore:section.interp
//#DiffIgnore:dynsym.__bss_start.section
//#DiffIgnore:dynsym._edata.section
//#DiffIgnore:dynsym._end.section
//#DiffIgnore:section.got
//#RunEnabled:false

// Do not export symbols for static executables: #836
//#Config:static-exe
//#Mode:static
//#LinkArgs:-z now --export-dynamic
//#RunEnabled:false
//#DoesNotContain:.dynamic

//#Config:select-symbols
//#LinkArgs:-z now --export-dynamic-symbol bar --export-dynamic-symbol baz
//#ExpectDynSym:bar
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:dynamic
//#Cross:false
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#RunEnabled:false

//#Config:select-symbols-list
//#LinkArgs:-z now --export-dynamic-symbol-list ./export-dynamic.def
//#ExpectDynSym:foo
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:dynamic
//#Cross:false
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#RunEnabled:false

//#Config:dynamic-symbols-list
//#LinkArgs:-z now -shared --dynamic-list ./export-dynamic.def
//#ExpectDynSym:foo
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:dynamic
//#Cross:false
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:file-header.entry
//#RunEnabled:false
// clang-format on

void foo(void) {};
void bar(void) {};
void baz(void) {};

void _start() { foo(); }
