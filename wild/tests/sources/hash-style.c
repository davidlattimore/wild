//#AbstractConfig:default
//#Object:runtime.c
//#Mode:dynamic
//#EnableLinker:lld
//#SkipLinker:ld
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:section.relro_padding
//#DiffIgnore:section.got.plt.entsize

//#Config:both-hashes:default
//#LinkArgs:--hash-style=both -shared -z now
//#Contains:.gnu.hash

//#Config:sysv-hash:default
//#LinkArgs:--hash-style=sysv -shared -z now
//#Contains:.hash
//#DoesNotContain:.gnu.hash

//#Config:gnu-hash:default
//#LinkArgs:--hash-style=gnu -shared -z now
//#Contains:.gnu.hash

int foo(void);

int call_foo(void) { return foo() + 2; }
