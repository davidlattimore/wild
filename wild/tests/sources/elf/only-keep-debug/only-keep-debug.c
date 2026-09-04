//#AbstractConfig:default
//#Object:runtime.c
//#CompArgs:-g
//#ReferenceLinkers:

//#Config:only-keep-debug:default
//#LinkArgs:--only-keep-debug
//#RunEnabled:false
//#DiffEnabled:false
//#TestOnlyKeepDebug:true
//#ExpectSym:_start
//#ExpectSym:exit_syscall
//#ExpectSection:.symtab

//#Config:only-keep-debug-compressed:default
//#LinkArgs:--only-keep-debug --compress-debug-sections=zlib
//#RunEnabled:false
//#DiffEnabled:false
//#TestOnlyKeepDebug:true
//#ExpectSym:_start

//#Config:only-keep-debug-build-id:default
//#LinkArgs:--only-keep-debug --build-id=0x123456789abcdef0
//#RunEnabled:false
//#DiffEnabled:false
//#TestOnlyKeepDebug:true
//#ExpectSym:_start

#include "../common/runtime.h"

int global_var = 42;

void _start(void) {
  runtime_init();
  exit_syscall(global_var);
}
