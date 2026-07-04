// Verify that consecutive RELR-eligible relocations are packed into bitmap
// entries rather than emitted as individual address entries.
// With bitmap packing, 4 consecutive pointers should produce 2 RELR entries
// (1 address + 1 bitmap) instead of 4 individual address entries.
//#Object:runtime.c
//#Mode:dynamic
//#LinkArgs:-pie -z now -z pack-relative-relocs
//#DiffMatchAny:true
// GNU ld ignores `-z pack-relative-relocs` on RISC-V.
//#ReferenceLinkers:lld
#include "../common/runtime.h"

// Four consecutive static pointers — eligible for RELR bitmap packing.
// These should produce 1 address entry + 1 bitmap entry (0x0f) in .relr.dyn,
// not 4 individual address entries.
static int a, b, c, d;
static int* p1 = &a;
static int* p2 = &b;
static int* p3 = &c;
static int* p4 = &d;
void _start(void) {
  runtime_init();
  // Verify pointers were correctly relocated at runtime.
  *p1 = 1;
  *p2 = 2;
  *p3 = 3;
  *p4 = 4;
  if (*p1 != 1) exit_syscall(1);
  if (*p2 != 2) exit_syscall(2);
  if (*p3 != 3) exit_syscall(3);
  if (*p4 != 4) exit_syscall(4);
  exit_syscall(42);
}
