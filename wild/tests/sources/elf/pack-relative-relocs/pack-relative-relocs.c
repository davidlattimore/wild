//#Config:default
//#Object:init.c
//#Shared:runtime.c
//#LinkArgs:-pie -z now -z pack-relative-relocs
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.got
//#RequiresGlibc:true
//#Mode:dynamic

#include "init.h"
#include "runtime.h"

int target = 42;

int foo = 0;
short bar = 0;
char baz = 0;

__attribute__((constructor)) static void ctor_foo(void) { foo = 1; }
__attribute__((constructor)) static void ctor_bar(void) { bar = 2; }
__attribute__((constructor)) static void ctor_baz(void) { baz = 3; }
__attribute__((destructor)) static void dtor_foo(void) { foo = 0; }

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
  call_init_functions();
  if (*aligned_ptr != target) exit_syscall(0);
  if (*unaligned_ptr_odd.foo != target) exit_syscall(1);
  if (*unaligned_ptr_even.foo != target) exit_syscall(2);
  if (foo != 1) exit_syscall(3);
  if (bar != 2) exit_syscall(4);
  if (baz != 3) exit_syscall(5);
  exit_syscall(target);
}
