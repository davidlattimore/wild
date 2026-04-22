// Several writable globals with different sizes and alignments — stresses
// `__data` layout under compat mode. In particular `aligned16` forces a
// 2^4 alignment step; wild's multi-part `DATA` section has to keep that
// alignment partition for the layout pass, so this catches regressions
// where the compat-mode alignment bump (for the DATA_CONST split) leaks
// into sections that shouldn't see page alignment.
#include <stdint.h>
int8_t b = 1;
int32_t w = 2;
int64_t q = 3;
int32_t arr[4] = {4, 5, 6, 7};
int64_t __attribute__((aligned(16))) aligned16 = 8;
int main(void) { return b + (int)w + (int)q + arr[3] + (int)aligned16 - 25; }
