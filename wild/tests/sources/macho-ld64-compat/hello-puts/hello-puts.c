// Third comparison test: exercises __stubs / __got / indirect
// symbol table via a libc call. This is the code path that the
// Rust-runtime TLS bug touches.
#include <stdio.h>
int main(void) {
  puts("hi");
  return 0;
}
