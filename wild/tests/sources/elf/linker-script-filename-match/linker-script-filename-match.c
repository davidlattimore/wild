//#LinkerScript:linker-script-filename-match.ld
//#Object:linker-script-filename-match-startup.c
//#Archive:linker-script-filename-match-app.c
//#Object:runtime.c
//#DiffIgnore:segment.LOAD.RW.alignment
//#SkipArch:riscv64
//#ExpectSym:startup_code section=".text.startup"
//#ExpectSym:app_code section=".text.app"
//#ExpectSym:begin_here section=".text"

#include "runtime.h"

extern int startup_code(void);
extern int app_code(void);

void begin_here(void) {
  int result = startup_code() + app_code();
  // startup_code returns 10, app_code returns 32. Sum = 42.
  exit_syscall(result);
}
