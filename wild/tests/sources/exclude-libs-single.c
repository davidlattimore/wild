//#LinkArgs:-z now -Bshareable --exclude-libs somelib
//#Mode:dynamic
//#RunEnabled:false
//#Archive:exclude-libs-single-1.c
//#ExpectDynSym:foo
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT

// Right now, we don't support excluding specific archives, so this only makes
// sure that `--exclude-libs archive` doesn't exclude symbols from all archives.
// FIXME: actually test and support excluding specific archives.

extern int foo(void);

// Use foo so that it's not garbage collected.
int call_foo(void) { return foo() + 2; }
