//#LinkArgs:-z now -Bshareable --exclude-libs somelib
//#Mode:dynamic
//#RunEnabled:false
//#Archive:exclude-libs-single-1.c
//#ExpectDynSym:foo
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT

extern int foo(void);

// Use foo so that it's not garbage collected.
int call_foo(void) { return foo() + 2; }
