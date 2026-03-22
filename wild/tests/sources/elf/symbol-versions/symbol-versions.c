//#AbstractConfig:verdef
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_FLAGS*
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:file-header.entry
//#Object:runtime.c

//#Config:verneed
//#Object:runtime.c
//#Object:symbol-versions-2.c
//#ExpectSym: _start section=".text"
//#ExpectSym: exit_syscall section=".text"
//#EnableLinker:lld

//#Config:verdef-0:verdef
//#TestUpdateInPlace:true
//#LinkArgs:--shared --version-script=./symbol-versions-script.map

//#Config:verdef-1:verdef
//#LinkArgs:--shared --soname=symbol-versions.so --version-script=./symbol-versions-script.map

//#Config:verdef-lto:verdef
//#RequiresLinkerPlugin:true
//#LinkerDriver:gcc
//#CompArgs:-flto -znow
//#LinkArgs:--shared -Wl,--version-script=./symbol-versions-script.map -flto

//#Config:with-escaping:verdef
//#LinkArgs:--shared --version-script=./symbol-versions-with-escaping.map

#include "runtime.h"

int foo(void);
int bar_global(void);
int bar_local(void);
int bar_v2(void);
int bar_v2_1(void);

void _start(void) {
  runtime_init();

  if (foo() != 2) {
    exit_syscall(foo());
  }
  if (bar_global() != 10) {
    exit_syscall(bar_global());
  }
  if (bar_local() != 11) {
    exit_syscall(bar_local());
  }
  if (bar_v2() != 12) {
    exit_syscall(bar_v2());
  }
  if (bar_v2_1() != 13) {
    exit_syscall(bar_v2_1());
  }

  exit_syscall(42);
}

int bar_global(void) { return 10; }

// TODO: doesn't work, the symbol is global
int bar_local(void) { return 11; }

int bar_v2(void) { return 12; }

int bar_v2_1(void) { return 13; }
