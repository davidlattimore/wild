//#RequiresWasiLibc:true
//#CompArgs: --target=wasm32-wasi -isystem $WASI_SYSROOT/include/wasm32-wasi
//#LinkArgs: $WASI_SYSROOT/lib/wasm32-wasi/crt1-command.o
//#Archive:template(-L$OUT_DIR -lhelper):libhelper.c
//#PostLinkArgs: -L$WASI_SYSROOT/lib/wasm32-wasi -lc
//#Contains: wasi_snapshot_preview1

#include <stdio.h>

const char* helper_greeting(void);
int helper_answer(void);

int main(void) {
  puts(helper_greeting());
  if (helper_answer() != 42) {
    return 1;
  }
  return 0;
}
