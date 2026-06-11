// Tests that .gdb_index address entries are assigned to the correct CU when a single input object
// contains multiple CUs. -ffunction-sections ensures each function gets a separate section so the
// per-CU assignment is observable in the address table.

//#CompArgs:-g -ggnu-pubnames -ffunction-sections
//#Object:runtime.c
//#Relocatable:multi-cu-a.c,multi-cu-b.c
//#SkipLinker:ld
//#LinkArgs:--gdb-index
//#ExpectSection:.gdb_index
// 4 CU indices expected: this file, runtime.c, multi-cu-a.c, and multi-cu-b.c.
//#ExpectGdbIndexDistinctAddrCus:4

#include "../common/runtime.h"

int multi_cu_a(int x);
int multi_cu_b(int x);

void _start(void) {
  runtime_init();
  if (multi_cu_a(21) != 42) {
    exit_syscall(10);
  }
  if (multi_cu_b(39) != 42) {
    exit_syscall(11);
  }
  exit_syscall(42);
}
