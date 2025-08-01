//#Shared:runtime.c
//#EnableLinker:lld
//#Mode:dynamic
//#LinkArgs:-z now
//#Shared:data-pointers-2.c
//#EnableLinker:lld
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
// GNU ld emits a .got section for the shared object, despite it not being
// necessary.
//#DiffIgnore:section.got

#include "runtime.h"

extern int foo[8];
extern int bar[8];

// Since `foo` and `bar` come from a shared object, this should result in a
// couple of runtime relocations in our data section. We have non-zero offsets
// relative to these symbols in order to make sure addends work as expected.
int *pointers[2] = {&foo[2], &bar[6]};

int check_pointers(int **p);

void _start(void) {
  runtime_init();

  exit_syscall(check_pointers(pointers));
}
