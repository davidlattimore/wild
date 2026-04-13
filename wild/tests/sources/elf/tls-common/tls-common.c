// When trying to merge this test with another one, make sure the input objects
// do not contain any section with TLS flag. This is necessary to fully stress
// the linker.
//#Config:default
//#LinkArgs:-z now
//#Mode:dynamic
//#Shared:runtime.c
//#DiffIgnore:section.rodata
//#DiffIgnore:section.got
//#DiffIgnore:.dynamic.*

// Make sure TLS variable is actually zero-initialized and
// not zero by pure chance because the elf binary contained a zero.
//#ExpectProgramHeader:PT_TLS filesz=0,memsz=4

#include "runtime.h"

__thread int tvar __attribute__((common));

void _start() {
  runtime_init();
  tvar += 42;
  exit_syscall(tvar);
}
