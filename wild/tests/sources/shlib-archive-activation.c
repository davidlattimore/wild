// Tests how undefined symbols in shared objects activate archive entries.

//#AbstractConfig:default
//#CompArgs:-fPIC
//#Object:runtime.c
//#Mode:dynamic
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:.dynamic.DT_NEEDED

//#Config:archive:default
//#Shared:shlib-archive-activation-1.c
//#Archive:shlib-archive-activation-2.c

#include "runtime.h"

int f1(void);

void _start(void) {
  runtime_init();

  // The second file is an archive. It will take priority over the shared object
  // even though the shared object is earlier.
  if (f1() != 10) {
    exit_syscall(101);
  }

  exit_syscall(42);
}
