// TODO: We don't emit fixups for `__tlv_bootstrap` yet, so we need to disable `RunEnabled` and
// `DiffEnabled` for now.
//#RunEnabled:false
//#DiffEnabled:false
//#Object:runtime.c
//#ExpectSection:__thread_data
//#ExpectSection:__thread_bss
//#ExpectSection:__thread_vars

#include "../common/runtime.h"

_Thread_local int initialized = 1;
_Thread_local int uninitialized __attribute__((aligned(64)));

void main(void) { exit_syscall(42); }
