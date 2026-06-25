//#AbstractConfig:default
//#CompArgs:-g -ggnu-pubnames
//#Object:runtime.c
//#Object:gdb-index2.c
//#ReferenceLinkers:lld

//#Config:enabled:default
//#LinkArgs:--gdb-index
//#DiffIgnore:section.gdb_index
//#ExpectSection:.gdb_index
//#ExpectGdbIndexCuCount:3
//#ExpectGdbIndexSymbol:compute
//#ExpectGdbIndexSymbol:_start
//#ExpectGdbIndexSymbol:foo
//#NoSection:.debug_gnu_pubnames
//#NoSection:.debug_gnu_pubtypes

//#Config:disabled:default
//#LinkArgs:--gdb-index --no-gdb-index
//#NoSection:.gdb_index
//#ExpectSection:.debug_gnu_pubnames
//#ExpectSection:.debug_gnu_pubtypes

//#Config:with-strip-debug:default
//#LinkArgs:--gdb-index --strip-debug
//#NoSection:.gdb_index

//#Config:with-strip-all:default
//#LinkArgs:--gdb-index --strip-all
//#DiffIgnore:file-header.entry
//#NoSection:.gdb_index

#include "../common/runtime.h"

int foo(int a, int b);

int compute(int x) { return x + 1; }

void _start(void) {
  runtime_init();
  if (compute(41) != 42) {
    exit_syscall(10);
  }
  if (foo(20, 22) != 42) {
    exit_syscall(11);
  }

  exit_syscall(42);
}
