// Adding shared libraries should yield dynamic executables: #836
//#Config:shared-input
//#LinkArgs:-z now --export-dynamic 
//#ExpectDynSym:foo
//#Shared:empty.c
//#Mode:unspecified
//#EnableLinker:lld
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

void foo(void) {};

void _start() {}
