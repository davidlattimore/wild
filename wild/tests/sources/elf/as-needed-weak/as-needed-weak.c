//#Object:runtime.c
//#Mode:dynamic
//#Shared:force-dynamic-linking.c
//#Shared:template(--push-state --as-needed $O --pop-state):as-needed-weak-lib.c
// Tests that --as-needed shared libraries are NOT activated for weak symbol
// references. This matches the behaviour of GNU ld and lld (mold differs).
// If fn1 is non-null the lib was incorrectly activated; exit with fn1() (1)
// so the test fails. If fn1 is null the lib was correctly excluded; exit 42.
// force-dynamic-linking.c is linked without --as-needed so both Wild and GNU
// ld produce a dynamic binary, enabling a meaningful diff.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.got
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:rel.undefined-weak.dynamic.R_X86_64_GLOB_DAT

#include "runtime.h"

__attribute__((weak)) int fn1(void);

void _start(void) {
  runtime_init();
  if (fn1) {
    exit_syscall(fn1());
  }
  exit_syscall(42);
}
