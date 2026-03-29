//#Config:default
//#Shared:runtime.c
//#LinkArgs:-pie -z now -z pack-relative-relocs
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
// TODO: copied from other test, check and remove unnecessary ones
//#DiffIgnore:segment.LOAD.RW.alignment
//#DiffIgnore:.dynamic.DT_PREINIT_ARRAY
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:section.got
//#RequiresGlibc:true
//#Mode:dynamic

#include "runtime.h"

int target = 42;

int* aligned_ptr = &target;

struct __attribute__((packed)) {
  char padding;
  int* foo;
} unaligned_ptr_odd = {
    .padding = 0,
    .foo = &target,
};

struct __attribute__((packed)) {
  short padding;
  int* foo;
} unaligned_ptr_even = {
    .padding = 0,
    .foo = &target,
};

void _start(void) {
  runtime_init();
  if (*aligned_ptr != target) exit_syscall(0);
  if (*unaligned_ptr_odd.foo != target) exit_syscall(1);
  if (*unaligned_ptr_even.foo != target) exit_syscall(2);
  exit_syscall(target);
}
