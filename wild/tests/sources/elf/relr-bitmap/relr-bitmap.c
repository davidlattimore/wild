// Verify that consecutive RELR-eligible relocations are packed into bitmap
// entries rather than emitted as individual address entries.
//
// Three consecutive constructors in .init_array produce function pointers at
// consecutive 8-byte-aligned offsets. Without bitmap packing, each would get
// its own RELR address entry. With packing, they share an address entry and
// a bitmap entry.
//#AbstractConfig:default
//#Object:runtime.c
//#Object:init.c:-fPIC
//#Mode:dynamic
//#LinkArgs:-pie -z now -z pack-relative-relocs --no-gc-sections
//#DiffMatchAny:true
// GNU ld ignores `-z pack-relative-relocs` on RISC-V.
//#ReferenceLinkers:lld
// Verify all 3 constructor pointers are correctly encoded as RELR relocations.
//#RelrCount:3

//#Config:x86_64:default
//#Arch:x86_64
//#ExpectSection:.relr.dyn max_entries=2

//#Config:aarch64:default
//#Arch:aarch64
//#ExpectSection:.relr.dyn max_entries=6

//#Config:loongarch64:default
//#Arch:loongarch64
//#ExpectSection:.relr.dyn max_entries=6

//#Config:riscv64:default
//#Arch:riscv64
//#ExpectSection:.relr.dyn max_entries=7

//#Config:ppc64le:default
//#Arch:ppc64le
//#ExpectSection:.relr.dyn max_entries=4
#include "../common/init.h"
#include "../common/runtime.h"

static int foo = 0;
static int bar = 0;
static int baz = 0;

// Three consecutive constructors — their function pointers go into .init_array
// at consecutive 8-byte-aligned offsets, making them RELR bitmap-packable.
__attribute__((constructor)) static void ctor_foo(void) { foo = 1; }
__attribute__((constructor)) static void ctor_bar(void) { bar = 2; }
__attribute__((constructor)) static void ctor_baz(void) { baz = 3; }

void _start(void) {
  runtime_init();
  call_init_functions();
  if (foo != 1) exit_syscall(1);
  if (bar != 2) exit_syscall(2);
  if (baz != 3) exit_syscall(3);
  exit_syscall(42);
}
