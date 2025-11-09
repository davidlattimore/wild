//#AbstractConfig:default
// TODO: #795
//#Arch: x86_64,aarch64

//#Config:strip-all:default
//#Object:runtime.c
//#LinkArgs:--strip-all
//#EnableLinker:lld
//#DiffIgnore:file-header.entry

//#Config:single-threaded:default
//#Object:runtime.c
//#WildExtraLinkArgs:--threads=1

//#Config:dev_null:default
//#Object:runtime.c
//#LinkArgs:-o /dev/null
//#DiffEnabled:false
//#RunEnabled:false

//#Config:gc-sections:default
//#CompArgs:-g -ffunction-sections
//#LinkArgs:--gc-sections
//#Object:runtime.c
//#NoSym:this_function_is_not_used

//#Config:no-args
//#AutoAddObjects:false
//#ExpectError:no input files

//#Config:no-mmap-output
//#Object:runtime.c
//#SkipLinker:ld
//#EnableLinker:lld
//#LinkArgs:--no-mmap-output-file

// The later --strip-all flag should override --strip-debug.
//#Config:strip-debug-strip-all
//#Object:runtime.c
//#LinkArgs:--strip-debug --strip-all
//#DiffIgnore:file-header.entry
//#NoSym:_start

// The later --strip-debug flag should override --strip-all.
//#Config:strip-all-strip-debug
//#Object:runtime.c
//#LinkArgs:--strip-all --strip-debug
//#ExpectSym:_start

//#Config:retain-symbols-file
//#Object:runtime.c
//#LinkArgs:--retain-symbols-file ./link_args.retain
//#ExpectSym:_start
//#ExpectSym:exit_syscall
//#NoSym:runtime_init

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}

void this_function_is_not_used(void) {}
