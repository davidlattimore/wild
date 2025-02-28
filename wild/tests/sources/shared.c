// We don't currently run this, we just make sure that we can produce a shared object and that it
// passes the diff test.
//
// One notable scenario that this test tests is having a non-weak undefined symbol (baz) in a shared
// object and having that symbol be defined by an archive entry that we don't load.

//#RunEnabled:false
//#LinkArgs:-shared -z now
//#Static:false
//#Archive:shared-a1.c,shared-a2.c
//#Shared:shared-s1.c
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:.dynamic.DT_NEEDED

int bar1(void);
int bar2(void);

int foo(void) {
    return bar1() + bar2();
}
