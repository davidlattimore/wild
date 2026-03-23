// A test for #1472.

//#Object:runtime.c
//#CompArgs:-fno-PIC
//#Mode:dynamic
//#Shared:force-dynamic-linking.c
//#DiffIgnore:section.got
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:rel.undefined-weak.dynamic.R_X86_64_GLOB_DAT

#include "runtime.h"

#define WEAK __attribute__((weak))

int WEAK foo(void);

void _start(void) {
  runtime_init();
  if (foo) {
    exit_syscall(foo());
  }
  exit_syscall(42);
}
