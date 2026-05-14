//#Config:default
//#RequiresLinkerPlugin:true
//#Object:runtime.c
//#LinkerDriver:gcc
//#CompArgs:-flto -O1
//#LinkArgs:-flto -O1 -nostdlib
//#DiffIgnore:section.got

#include "../common/runtime.h"

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
