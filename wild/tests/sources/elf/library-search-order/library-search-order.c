// Tests that library search order is directory-first, with shared objects preferred only within
// each directory.

//#CompArgs:-fPIC
//#Object:runtime.c
//#Mode:unspecified
//#SoSingleLinker:ld
//#Archive:as(first/libfoo.a),noadd:from-archive.c
//#Shared:as(second/libfoo.so),template(-L$OUT_DIR/first -L$OUT_DIR/second -lfoo):from-shared.c
//#ExpectSym:selected_from_archive

#include "../common/runtime.h"

int foo(void);

void _start(void) {
  runtime_init();
  exit_syscall(foo());
}
