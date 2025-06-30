//#AbstractConfig:default
// We match lld's behaviour, not GNU ld's for --allow-shlib-undefined. That is, we only validate
// shared object undefined symbols when all of the shared object's direct dependencies are loaded.
//#EnableLinker:lld
//#SkipLinker:ld
//#Object:runtime.c
//#Mode:dynamic
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:.dynamic.DT_NEEDED
// Ignore a few things that lld does differently.
//#DiffIgnore:section.relro_padding
//#DiffIgnore:section.got.plt.entsize
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#RunEnabled:false
// Cross doesn't currently support lld and this test doesn't use GNU ld.
//#Cross:false

// Allow linking against shared object with undefined symbols. We don't run this because the runtime
// linker would error due to the undefined symbol.
//#Config:allow:default
//#Shared:shlib-undefined-2.c
//#LinkArgs:--allow-shlib-undefined -z now

// This should also succeed to link because our shared object depends on another shared object that
// we don't have loaded.
//#Config:disallow-incomplete:default
//#Shared:shlib-undefined-2.c
//#LinkArgs:--no-allow-shlib-undefined

// Disallow linking against shared object with undefined symbols. In this variant, the shared object
// (2) that we depend on has all of its dependencies (3) also loaded.
//#Config:disallow-complete:default
//#Shared:shlib-undefined-2.c
//#Shared:shlib-undefined-3.c
//#LinkArgs:--no-allow-shlib-undefined
//#ExpectError:def2

//#Config:shared:default
//#Shared:shlib-undefined-2.c
//#LinkArgs:-z now -shared
//#RunEnabled:false
// TODO: GNU ld sets the entry to _start even though we're writing a shared object. We probably
// should too.
//#DiffIgnore:file-header.entry

#include "runtime.h"

int def1(void) {
    return 100;
}

int call_def1(void);

void _start(void) {
    runtime_init();
    exit_syscall(call_def1());
}
