//#AbstractConfig:default
//#RequiresLinkerPlugin:true

// LTO object referencing versioned symbols from a regular object
//#Config:lto-ref-regular:default
//#LinkerDriver:gcc
//#Object:runtime.c
//#Object:lto-symver-1.c
//#Object:lto-symver-2.c:-flto
//#Object:lto-symver-3.c
//#LinkArgs:-flto -nostdlib -Wl,--version-script=./lto-symver.map,-znow
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:section.got

// LTO object referencing versioned symbols from a shared object
//#Config:clang-lto-ref-shared:default
//#Mode:dynamic
//#Compiler:clang
//#LinkerDriver:clang
//#SkipLinker:ld
//#EnableLinker:lld
//#Object:runtime.c
//#Object:lto-symver-2.c:-flto
//#Shared:lto-symver-1.c
//#Object:lto-symver-3.c
//#LinkArgs:-flto -nostdlib -Wl,--version-script=./lto-symver.map,-znow
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.got.plt.entsize
//#DiffIgnore:section.gnu.version_d.alignment
//#DiffIgnore:section.gnu.version_r.alignment
//#DiffIgnore:version_d.verdef_1
//#RequiresGlibc:true

// LTO object referencing versioned symbols from a non-LTO archive that in turn
// references a symbol from an LTO archive.
//#AbstractConfig:lto-ref-archive-ref-lto:default
//#Mode:dynamic
//#LinkerDriver:gcc
//#Object:runtime.c
//#Object:lto-symver-2.c:-flto
//#Archive:lto-symver-1.c
//#Archive:lto-symver-3.c:-flto
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:section.got

//#Config:clang-lto-ref-archive-ref-lto:lto-ref-archive-ref-lto
//#LinkerDriver:clang
//#SkipLinker:ld
//#EnableLinker:lld
//#Compiler:clang
//#DiffIgnore:section.eh_frame.type
//#LinkArgs:-flto -nostdlib -Wl,-znow

#include "runtime.h"

int call_versioned_symbols(void);

void _start(void) {
  runtime_init();
  exit_syscall(call_versioned_symbols());
}
