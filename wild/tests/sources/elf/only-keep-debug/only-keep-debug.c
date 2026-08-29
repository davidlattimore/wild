//#AbstractConfig:default
//#Object:runtime.c
//#ReferenceLinkers:

//#Config:only-keep-debug:default
//#LinkArgs:--only-keep-debug
//#RunEnabled:false
//#DiffEnabled:false
//#ExpectSym:_start
//#ExpectSym:exit_syscall
//#ExpectProgramHeader:LOAD file-size=0

#include "../common/runtime.h"

int global_var = 42;

void _start(void) {
  runtime_init();
  exit_syscall(global_var);
}
