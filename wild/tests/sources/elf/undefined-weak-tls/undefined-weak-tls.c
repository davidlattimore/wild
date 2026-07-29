//#CompArgs:-ftls-model=local-exec
//#LinkArgs:-z now --no-gc-sections
//#Object:runtime.c
//#Object:ptr_black_box.c
//#ReferenceLinkers:bfd,lld
//#SkipArch:ppc64le
//#ExpectSym:undefined_tls_address

#include "../common/runtime.h"

extern __thread int undefined_tls __attribute__((weak, visibility("hidden")));

// There's not really any way to check any property of this symbol, so we pretty much just make sure
// that we can link and that the function that references the symbol was included.
void* undefined_tls_address(void) { return &undefined_tls; }

// Make sure the TLS segment isn't empty.
__thread int defined_tls;

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
