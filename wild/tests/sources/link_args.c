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

#include "runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}

void this_function_is_not_used(void) {}
