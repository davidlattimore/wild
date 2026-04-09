//#AbstractConfig:default
//#RequiresLinkerPlugin:true
//#RequiresCompilerFlags:-flto=auto -fno-fat-lto-objects
//#DiffEnabled:false
//#RunEnabled:false
//#SkipLinker:ld

//#Config:gcc:default
//#CompArgs:-O2 -g -DRELDEBUG -flto=auto -fno-fat-lto-objects
//#Object:runtime.c
//#LinkerDriver:gcc
//#LinkArgs:-flto=auto -nostdlib -Wl,--export-dynamic -rdynamic
//#ExpectSym:debug_sym section=".debug_info"

#include "runtime.h"

int debug_sym __attribute__((used, section(".debug_info"))) = 123;

int foo() { return 42; }

void _start(void) {
  runtime_init();
  exit_syscall(foo());
}
