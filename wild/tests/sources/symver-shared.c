// This test has two shared objects. One contains an undefined symbol
// foo@@VER_1.0, the other contains the definition foo@VER_1.0. Note that the
// definition with a single '@' is not the default version. i.e. it doesn't bind
// 'foo'.

//#Object:runtime.c
//#Shared:symver-shared-1.c
//#Shared:symver-shared-2.c
//#Mode:dynamic
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:section.got
//#LinkArgs:--version-script=./symver-shared.map -znow
//#RequiresGlibc:true

#include "runtime.h"

int call_foo_v1(void);

void _start(void) {
  runtime_init();
  exit_syscall(call_foo_v1());
}
