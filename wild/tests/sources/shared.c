// We don't currently run this, we just make sure that we can produce a shared
// object and that it passes the diff test.
//
// One notable scenario that this test tests is having a non-weak undefined
// symbol (baz) in a shared object and having that symbol be defined by an
// archive entry that we don't load.

//#Config:default
//#RunEnabled:false
//#LinkArgs:-shared -z now
//#Mode:dynamic
//#Shared:shared-s1.c
//#Archive:shared-a1.c,shared-a2.c
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:.dynamic.DT_NEEDED

//#Config:symbolic:default
//#LinkArgs:-shared -z now -Bsymbolic
//#DiffIgnore:.dynamic.DT_FLAGS.SYMBOLIC
//#DiffIgnore:.dynamic.DT_SYMBOLIC
//#DiffIgnore:section.got
//#DiffIgnore:rel.R_X86_64_PC32.R_X86_64_PLT32
//#DiffIgnore:rel.extra-opt.R_AARCH64_CALL26.ReplaceWithNop.invalid-shared-object

//#Config:symbolic-functions:default
//#LinkArgs:-shared -z now -Bsymbolic-functions

//#Config:nosymbolic:default
//#LinkArgs:-shared -z now -Bno-symbolic

// TODO: Add a test for `-Bsymbolic-non-weak`. The lld included in Ubuntu 22.04
// is old and doesn't implement the `-Bsymbolic-non-weak` option.

//#Config:symbolic-non-weak-functions:default
//#LinkArgs:-shared -z now -Bsymbolic-non-weak-functions
//#SkipLinker:ld
//#EnableLinker:lld
//#DiffIgnore:section.relro_padding
//#DiffIgnore:section.got.plt.entsize
//#DiffIgnore:dynsym.baz.section

int bar1(void);
int bar2(void);

int foo(void) { return bar1() + bar2(); }

int call_bar1(void) { return bar1(); }
