//#AbstractConfig:default
//#Object:runtime.c

//#Config:undefined:default
//#LinkArgs:--undefined=foo -u bar -ubaz
//#ExpectSym:foo
//#ExpectSym:bar
//#ExpectSym:baz

// Verify that we can activate an archive entry by listing a symbol it defines
// as undefined.
//#Config:archive-activation:default
//#Archive:archive_activation0.c
//#CompArgs:-DEXPECT_ARCH0
//#LinkArgs:--undefined=bar

#include "runtime.h"

__attribute__((weak)) int is_archive0_loaded() { return 0; }

void _start(void) {
  runtime_init();

#ifdef EXPECT_ARCH0
  if (!is_archive0_loaded()) {
    exit_syscall(10);
  }
#endif

  exit_syscall(42);
}
