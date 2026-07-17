//#RequiresWasiLibc:true
//#CompArgs: --target=wasm32-wasi -isystem $WASI_SYSROOT/include/wasm32-wasi
//#LinkArgs: $WASI_SYSROOT/lib/wasm32-wasi/crt1-command.o
//#PostLinkArgs: -L$WASI_SYSROOT/lib/wasm32-wasi -lc

#include <stdlib.h>
#include <string.h>

int main(void) {
  char* p = malloc(64);
  if (p == NULL) {
    return 101;
  }
  memset(p, 0xab, 64);
  if ((unsigned char)p[0] != 0xab || (unsigned char)p[63] != 0xab) {
    return 102;
  }
  free(p);

  /* Large enough to stress sbrk / memory.grow beyond a tiny initial window. */
  char* q = malloc(256 * 1024);
  if (q == NULL) {
    return 103;
  }
  q[0] = 1;
  q[256 * 1024 - 1] = 2;
  free(q);
  return 0;
}
