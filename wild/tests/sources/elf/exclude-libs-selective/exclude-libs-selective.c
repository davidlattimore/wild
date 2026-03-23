//#LinkArgs:-z now -Bshareable --exclude-libs exclude-libs-selective-excluded.a
//#Mode:dynamic
//#RunEnabled:false
//#Archive:exclude-libs-selective-excluded.c
//#Archive:exclude-libs-selective-included.c
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#ExpectDynSym:included_fn
//#NoDynSym:excluded_fn

extern int excluded_fn(void);
extern int included_fn(void);

int call_fns(void) { return excluded_fn() + included_fn(); }
