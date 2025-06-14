// Adding shared libraries should yield dynamic executables: #836
//#Config:export-dynamic
//#LinkArgs:-z now --export-dynamic 
//#ExpectDynSym:foo
//#Shared:empty.c
//#Static:false
//#EnableLinker:lld
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#RunEnabled:false

// Do not export symbols for static executables: #836
//#Config:export-dynamic-static-exe
//#LinkArgs:-z now --export-dynamic 
//#RunEnabled:false
//#DoesNotContain:.dynamic

void foo(void) {};

void _start() {}