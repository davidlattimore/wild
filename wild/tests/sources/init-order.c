//#Object:runtime.c
//#Object:init.c
//#Object:init-order-2.c
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata

#include "init.h"
#include "runtime.h"

static int ctors_init_val = 0;

// Constructors

__attribute__((constructor)) void init_a() {}
__attribute__((constructor)) void init_b() {}
__attribute__((constructor(1000))) void init_1000a() {}
__attribute__((constructor(1000))) void init_1000b() {}
__attribute__((constructor(2000))) void init_2000a() {}
__attribute__((constructor(2000))) void init_2000b() {}
__attribute__((constructor(65535))) void init_65535a() {}

// Destructors

__attribute__((destructor)) void fini_a() {}
__attribute__((destructor)) void fini_b() {}
__attribute__((destructor(1000))) void fini_1000a() {}
__attribute__((destructor(1000))) void fini_1000b() {}
__attribute__((destructor(2000))) void fini_2000a() {}
__attribute__((destructor(2000))) void fini_2000b() {}
__attribute__((destructor(65535))) void fini_65535a() {}

void _start(void) {
  runtime_init();
  call_init_functions();
  // This test currently just relies on linker-diff to verify the init_array and
  // fini_array orderings.
  exit_syscall(42);
}