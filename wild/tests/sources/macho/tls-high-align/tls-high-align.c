// Exercises the interaction between a high-alignment tbss section
// and multi-object linking. The tdata inputs come from two
// objects (each contributing a differently-aligned tdata var) so
// the linker must merge them before placing tbss. If the TLV
// template-offset helper disagrees between the `$tlv$init` symbol-
// resolution path and the in-place reloc patcher, write-through
// reads here catch it.
//
//#Object:tls-high-align1.c
//#Object:tls-high-align2.c

#include <stdint.h>
#include <stdio.h>

extern __thread int a_i32;
extern __thread long a_i64;
extern __thread long long wide_tbss[4];

int main(void) {
  if (a_i32 != 1) {
    fprintf(stderr, "a_i32=%d\n", a_i32);
    return 1;
  }
  if (a_i64 != 2) {
    fprintf(stderr, "a_i64=%ld\n", a_i64);
    return 2;
  }
  for (int i = 0; i < 4; i++) {
    if (wide_tbss[i] != 0) {
      fprintf(stderr, "wide_tbss[%d]=%lld\n", i, wide_tbss[i]);
      return 3;
    }
  }
  // Round-trip writes: if offsets alias, this trips.
  a_i32 = 0x1234;
  a_i64 = 0x5678DEADBEEFLL;
  for (int i = 0; i < 4; i++) {
    wide_tbss[i] = 0x1000LL + i;
  }
  if (a_i32 != 0x1234) return 4;
  if (a_i64 != 0x5678DEADBEEFLL) return 5;
  for (int i = 0; i < 4; i++) {
    if (wide_tbss[i] != 0x1000LL + i) return 6 + i;
  }
  return 42;
}
