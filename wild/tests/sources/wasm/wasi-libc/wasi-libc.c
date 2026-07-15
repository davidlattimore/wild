//#RequiresWasiLibc:true
//#CompArgs: --target=wasm32-wasi -isystem $WASI_SYSROOT/include/wasm32-wasi
//#LinkArgs: $WASI_SYSROOT/lib/wasm32-wasi/crt1-command.o
//#PostLinkArgs: -L$WASI_SYSROOT/lib/wasm32-wasi -lc
//#Contains: wasi_snapshot_preview1

#include <stdio.h>

int main(void) {
  puts("hello-wasi");
  printf("answer=%d\n", 42);
  return 0;
}
