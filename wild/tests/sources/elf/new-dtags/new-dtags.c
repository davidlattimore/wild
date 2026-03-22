//#AbstractConfig:default
//#Object:runtime.c
//#Mode:dynamic
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT

//#Config:new-dtags:default
//#LinkArgs:-shared -rpath /test/path --enable-new-dtags -z now
//#ExpectDynamic:DT_RUNPATH
//#ExpectDynamic:DT_FLAGS
//#ExpectDynamic:DT_FLAGS_1
//#NoDynamic:DT_RPATH
//#NoDynamic:DT_BIND_NOW

//#Config:old-dtags:default
//#LinkArgs:-shared -rpath /test/path --disable-new-dtags -z now
//#ExpectDynamic:DT_RPATH
//#ExpectDynamic:DT_BIND_NOW
//#ExpectDynamic:DT_FLAGS_1
//#NoDynamic:DT_RUNPATH
//#NoDynamic:DT_FLAGS
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#DiffIgnore:.dynamic.DT_RPATH

int foo(void);

int call_foo(void) { return foo() + 2; }
