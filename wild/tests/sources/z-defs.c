//#Config:z-defs
//#LinkArgs:-Bshareable -z now -z defs
//#Mode:dynamic
//#RunEnabled:false
//#ExpectError:foo

//#Config:z-undefs
//#LinkArgs:-Bshareable -z now -z undefs
//#Mode:dynamic
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT

int foo(void);

int call_foo(void) { return foo() + 2; }
