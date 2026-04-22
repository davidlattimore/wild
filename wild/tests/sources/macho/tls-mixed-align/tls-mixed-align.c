// Tests that a __thread_data (initialized TLS) variable and a
// __thread_bss (zero-init) variable with *larger* alignment don't
// end up at per-thread offsets that contradict their declared
// layout.
//
// Regression: wild computed the TLV template offset for tbss-backed
// variables as `round_up(tdata.size, tbss.align) +
//                  (var.addr - tbss.start)`.
// That formula equals the correct `var.addr - tdata.start` only
// when `tdata.start % tbss.align == 0`. When it isn't, wild wrote
// an offset past the end of the per-thread buffer that dyld
// allocates (`initialContentSize = tbss.end - tdata.start`), so
// every access to the tbss variable either read from a tdata
// neighbour or ran off the end of the malloc chunk.
//
// ld64's rule (see ld64 ld.cpp:1145, rdar://24221680) is to promote
// both __thread_data and __thread_bss to the max of their
// alignments, guaranteeing the gap matches `padded_tdata_size`.
//
//#Object:tls-mixed-align1.c

#include <stdint.h>
#include <stdio.h>

extern __thread int tdata_small;
extern __thread long long tbss_wide[2];

int main(void) {
  if (tdata_small != 7) {
    fprintf(stderr, "tdata_small=%d expected 7\n", tdata_small);
    return 1;
  }
  if (tbss_wide[0] != 0 || tbss_wide[1] != 0) {
    fprintf(stderr, "tbss_wide not zero: [%lld,%lld]\n", tbss_wide[0],
            tbss_wide[1]);
    return 2;
  }
  if (((uintptr_t)&tbss_wide[0]) & 15) {
    fprintf(stderr, "tbss_wide @ %p is 16-misaligned\n", (void*)&tbss_wide[0]);
    return 3;
  }
  tdata_small = 42;
  tbss_wide[0] = 0x1111222233334444LL;
  tbss_wide[1] = 0x5555666677778888LL;
  if (tdata_small != 42) {
    fprintf(stderr, "tdata_small clobbered: %d\n", tdata_small);
    return 4;
  }
  if (tbss_wide[0] != 0x1111222233334444LL ||
      tbss_wide[1] != 0x5555666677778888LL) {
    fprintf(stderr, "tbss_wide readback mismatch: [%llx,%llx]\n", tbss_wide[0],
            tbss_wide[1]);
    return 5;
  }
  return 42;
}
