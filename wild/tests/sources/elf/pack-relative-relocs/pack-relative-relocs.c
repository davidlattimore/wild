// This test verifies that we correctly handle RELR relocations in a few edge
// cases.
//#Object:init.c:-fPIC
//#Shared:runtime.c
//#LinkArgs:-pie -z now -z pack-relative-relocs
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.got
//#DiffIgnore:rel.R_AARCH64_ADR_GOT_PAGE.R_AARCH64_ADR_GOT_PAGE
//#Mode:dynamic
// Ubuntu 24.04's GNU ld doesn't crate .rela.dyn for AArch64.
//#RequiresGlibcVersion:2.40
//#ExpectDynamic:DT_RELR
//#ExpectDynamic:DT_RELRSZ
//#ExpectDynamic:DT_RELRENT
//#Contains:.relr.dyn
//#SkipArch:riscv64

#include "init.h"
#include "runtime.h"

int target = 42;

// Typical aligned pointer; will result in RELR for .data that is multiple of 8.
int* aligned_ptr = &target;

// Unaligned pointer with odd address; will result in RELA for .data.
struct __attribute__((packed)) {
  char padding;
  int* foo;
} unaligned_ptr_odd = {
    .padding = 0,
    .foo = &target,
};

// Unaligned pointer with even address; will result in RELR for .data that is
// not multiple 8 and cannot be packed.
struct __attribute__((packed)) {
  short padding;
  int* foo;
} unaligned_ptr_even = {
    .padding = 0,
    .foo = &target,
};

int foo = 0;
short bar = 0;
char baz = 0;

// Init array that is susceptible to packing.
__attribute__((constructor)) static void ctor_foo(void) { foo = 1; }
__attribute__((constructor)) static void ctor_bar(void) { bar = 2; }
__attribute__((constructor)) static void ctor_baz(void) { baz = 3; }
// Due to how we process inputs at the time of writing this test, single
// destructor goes through the layout phase before the constructors, but is
// written after them. This nicely captures mismatches in RELR handling between
// stages.
__attribute__((destructor)) static void dtor_foo(void) { foo = 0; }

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
