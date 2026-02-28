//#AbstractConfig:default
//#Object:runtime.c
//#Object:gdb-index-2.c
//#SkipLinker:ld
//#DiffEnabled:false
//#RunEnabled:false

//#Config:multi-cu:default
//#CompArgs:-g
//#LinkArgs:--gdb-index
//#DiffIgnore:section.gdb_index
//#ExpectSection:.gdb_index
//#ValidateGdbIndex:true
//#ExpectGdbIndexCuCount:3
//#TestUpdateInPlace:true

//#Config:no-debug-info:default
//#LinkArgs:--gdb-index
//#NoSection:.gdb_index

#include "runtime.h"

int math_add(int a, int b);
int math_mul(int a, int b);

void _start(void) {
  runtime_init();
  int result = math_add(1, 2) + math_mul(3, 4);
  exit_syscall(result);
}
