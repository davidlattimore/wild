//#Object:runtime.c
//#Mode:dynamic
//#CompSoArgs:-fPIC
//#Shared:symbol-priority-d1.c
//#Shared:symbol-priority-d2.c
//#Shared:symbol-priority-d3.c
//#Object:symbol-priority-s1.c
//#Object:symbol-priority-s2.c
//#Object:symbol-priority-s3.c
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.got

#include "runtime.h"

// This function is defined weakly in all the files, except the last shared
// object, which defines it strongly. The definition used should be the first
// one that isn't from a shared object. It doesn't matter that it's weak since
// there are no strong definitions in regular objects.
int v1(void);

// This symbol is defined in all the shared objects. The first shared object
// defines it weakly as data. The second and third defines it strongly as a
// function. Because these definitions are from shared objects, weak vs strong
// doesn't affect which we select, so the first definition should be chosen. We
// shouldn't error despite having two strong definitions, since both are from
// shared objects. We have a direct reference to the symbol, so will need a copy
// relocation. Having data and functions with the same name isn't something we'd
// expect to see, however it's a useful way to verify that we're selecting the
// symbol from expected shared object.
extern int v2[];

void _start(void) {
  runtime_init();

  if (v1() != 13) {
    exit_syscall(v1());
  }

  if (v2[1] != 20) {
    exit_syscall(5);
  }

  exit_syscall(42);
}
