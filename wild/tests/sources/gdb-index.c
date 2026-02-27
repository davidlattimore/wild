// Test .gdb_index section generation with --gdb-index.

//#AbstractConfig:default
//#Object:runtime.c
//#Object:gdb-index-2.c
//#SkipLinker:ld
//#RunEnabled:false

// Config: multiple CUs with debug info — .gdb_index must be present.
//#Config:multi-cu:default
//#CompArgs:-g
//#LinkArgs:--gdb-index
//#DiffIgnore:section.gdb_index
//#ExpectSection:.gdb_index

// Config: --gdb-index without debug info — section should still be present
// (header + empty CU list).
//#Config:no-debug-info:default
//#LinkArgs:--gdb-index
//#DiffIgnore:section.gdb_index
//#ExpectSection:.gdb_index

#include "runtime.h"

int math_add(int a, int b);
int math_mul(int a, int b);

void _start(void) {
  runtime_init();
  int result = math_add(1, 2) + math_mul(3, 4);
  exit_syscall(result);
}
