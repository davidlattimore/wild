//#Config:default
//#LinkArgs:-z now -Bshareable --exclude-libs exclude-libs-selective-excluded.a
//#Mode:dynamic
//#RunEnabled:false
//#Archive:exclude-libs-selective-excluded.c
//#Archive:exclude-libs-selective-included.c
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#ExpectDynSym:included_fn
//#NoDynSym:excluded_fn

// --whole-archive should not cause us to treat an archive like it's not an
// archive for the purposes of --exclude-libs.
//#Config:whole-archive:default
//#LinkArgs:-z now -Bshareable --whole-archive --exclude-libs exclude-libs-selective-excluded.a

extern int excluded_fn(void);
extern int included_fn(void);

int call_fns(void) { return excluded_fn() + included_fn(); }
