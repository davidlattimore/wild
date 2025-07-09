// clang-format off
// Adding shared libraries should yield dynamic executables: #836
//#Config:shared-input
//#LinkArgs:-z now --export-dynamic
//#ExpectDynSym:foo
//#Shared:empty.c
//#Mode:unspecified
//#EnableLinker:lld
//#Cross:false
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
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
//#Mode:unspecified
//#EnableLinker:lld
//#Cross:false
//#DiffIgnore:.dynamic.DT_NEEDED
//#RunEnabled:false

//#Config:select-symbols-list
//#LinkArgs:-z now --export-dynamic-symbol-list ./export-dynamic.def
//#ExpectDynSym:foo
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:unspecified
//#EnableLinker:lld
//#Cross:false
//#DiffIgnore:.dynamic.DT_NEEDED
//#RunEnabled:false

//#Config:wip
//#LinkArgs:-z now --dynamic-list ./export-dynamic.def
//#ExpectDynSym:foo
//#ExpectDynSym:baz
//#Shared:empty.c
//#Mode:unspecified
//#EnableLinker:lld
//#Cross:false
//#DiffIgnore:.dynamic.DT_NEEDED
//#RunEnabled:false
// clang-format on

void foo(void) {};
void bar(void) {};
void baz(void) {};

void _start() {}
