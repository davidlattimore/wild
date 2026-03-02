//#AbstractConfig:default
// TODO: Investigate why we don't emit _IO_stdin_used which is in .rodata.
//#DiffIgnore:section.rodata
//#DiffIgnore:section.got
//#RequiresLinkerPlugin:true

//#AbstractConfig:error

//#Config:gcc:default
//#CompArgs:-flto
//#Object:runtime.c
//#Object:linker-plugin-lto-2.c
//#LinkerDriver:gcc
//#LinkArgs:-flto -nostdlib -znow

//#Config:clang:default
//#Compiler:clang
//#CompArgs:-flto
//#LinkerDriver:clang
//#LinkArgs:-Wl,-znow -flto -nostdlib -O0
//#Object:runtime.c
//#Object:linker-plugin-lto-2.c
//#DiffIgnore:section.eh_frame.type

//#Config:clang-link-gcc:error
//#Compiler:clang
//#CompArgs:-flto
//#LinkerDriver:gcc
//#SkipLinker:ld
//#LinkArgs:-Wl,-znow -flto -nostdlib
//#Object:runtime.c
//#Object:linker-plugin-lto-2.c
//#ExpectError:(contains LLVM-IR, but the linker plugin|Wild was compiled without linker-plugin support)

//#Config:gcc-link-clang:error
//#Compiler:gcc
//#CompArgs:-flto
//#LinkerDriver:clang
//#SkipLinker:ld
//#LinkArgs:-Wl,-znow -flto -nostdlib
//#Object:runtime.c
//#Object:linker-plugin-lto-2.c
//#ExpectError:(contains GCC-IR, but the linker plugin|Wild was compiled without linker-plugin support)
//#Cross:false

// LTO, but no linker plugin was supplied by the compiler. We could try to find
// the plugin ourselves, but we don't currently support that.
//#Config:clang-no-plugin:error
//#Compiler:clang
//#CompArgs:-flto
//#LinkerDriver:clang
//#SkipLinker:ld
//#LinkArgs:-Wl,-znow -nostdlib
//#Object:runtime.c
//#Object:linker-plugin-lto-2.c
//#ExpectError:(contains LLVM-IR, but linker plugin was not supplied|Wild was compiled without linker-plugin support)

// The only LTO input is in an archive and we end up not using it.
//#Config:clang-empty-lto:default
//#Compiler:clang
//#Object:runtime.c
//#Archive:empty.c:-flto
//#Object:linker-plugin-lto-2.c
//#SkipLinker:ld
//#LinkerDriver:clang
//#LinkArgs:-flto -nostdlib
//#DiffEnabled:false

// The only LTO input is in an archive and we end up not using it.
//#Config:gcc-empty-lto:default
//#Compiler:gcc
//#Object:runtime.c
//#Archive:empty.c:-flto
//#Object:linker-plugin-lto-2.c
//#LinkerDriver:gcc
//#LinkArgs:-flto -nostdlib -znow

#include "runtime.h"

int foo();

void _start(void) {
  runtime_init();
  exit_syscall(foo());
}
