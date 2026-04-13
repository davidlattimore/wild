// An archive and a shared object both define `foo`. The archive entry is never
// loaded, so the definition from the shared object is the one that's used. The
// symbol in the archive is hidden. Makes sure we don't incorrectly allow the
// hidden attribute from the archive to affect the reference to the dynamic
// symbol.

//#Object:runtime.c
//#Mode:dynamic
//#Shared:call-hidden-archive-lib.c
//#Archive:call-hidden-archive-archive.c
//#SoSingleLinker:ld
//#DiffIgnore:.dynamic.DT_RELA*

#include "../common/runtime.h"

int foo(void);

void _start(void) {
  runtime_init();

  if (foo() != 42) {
    exit_syscall(1);
  }

  exit_syscall(42);
}
