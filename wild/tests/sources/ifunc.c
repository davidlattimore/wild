//#AbstractConfig:default
//#Object:ifunc1.c
//#Object:ifunc_init.c
//#Object:runtime.c
//#DiffIgnore:section.rela.plt.link
//#RequiresGlibc:true
//#Arch: x86_64

//#Config:pie:default
//#CompArgs:-fpie -ffunction-sections
// This can be in any test that's x86_64 only.
//#ExpectSym:_GLOBAL_OFFSET_TABLE_

//#Config:no-pie:default
//#CompArgs:-fno-pie

//#Config:got-plt-syms:default
//#LinkArgs:--got-plt-syms
//#SkipLinker:ld
//#TestUpdateInPlace:true
//#DiffEnabled:false
//#ExpectSym:compute_value10$got section=".got"
//#ExpectSym:compute_value32$got section=".got"
//#NoSym:compute_unused$got
//#ExpectSym:compute_value10$plt section=".plt.got"
//#ExpectSym:compute_value32$plt section=".plt.got"
//#NoSym:compute_unused$plt

#include "ifunc_init.h"
#include "init.h"
#include "runtime.h"

extern int compute_value10(void);
extern int compute_value32(void);

extern int resolve_count;

typedef int (*vptr)(void);

const vptr v10_ptr = compute_value10;

void _start(void) {
  runtime_init();

  int rv = init_ifuncs();
  if (rv != 0) {
    exit_syscall(rv);
  }
  if (compute_value10() != 10) {
    exit_syscall(1);
  }
  if (compute_value32() != 32) {
    exit_syscall(2);
  }
  if (v10_ptr() != 10) {
    exit_syscall(3);
  }
  if (resolve_count != 2) {
    exit_syscall(4);
  }
  if (v10_ptr == compute_value32) {
    exit_syscall(5);
  }
  if (v10_ptr != compute_value10) {
    exit_syscall(5);
  }
  exit_syscall(42);
}
