//#LinkerDriver:clang
// Regression: the __mod_term_func section emitted for FINI_ARRAY
// must carry flags S_MOD_TERM_FUNC_POINTERS (0x0A), not 0x0E
// (= S_16BYTE_LITERALS). Wild previously mis-encoded the flag,
// which defeated the `is_const_pointer_flags` check in
// `write_headers` — FINI_ARRAY got classified as writable and
// stayed in __DATA while the layout pass had placed it in
// __DATA_CONST's VM range. dyld then rejected the binary at
// load with:
//   section '__mod_term_func' start address is before
//   containing segment's address
//
// To tickle the bug we need BOTH:
//   1. a destructor (populates FINI_ARRAY / __mod_term_func)
//   2. a dylib call (populates __got, forcing the __DATA_CONST
//      + __DATA split in the writer)
#include <stdio.h>
__attribute__((destructor)) static void finish(void) {
  // Non-inlinable libc call so the destructor stays in the output.
  int x = ftell(stderr);
  (void)x;
}
int main(void) {
  // Another libc call — forces a __got entry and gives us non-empty
  // __DATA_CONST so the writer splits __DATA_CONST + __DATA.
  printf("%d", 42);
  return 42;
}
