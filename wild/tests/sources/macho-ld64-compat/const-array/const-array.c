// `const` array → ends up in `__TEXT,__const` (read-only, non-literal
// data). Different from `__cstring` literals; catches bugs in the
// RODATA-vs-DATA_REL_RO routing where pointer-free const data should
// stay in __TEXT and not leak into the writable segment.
const int primes[5] = {2, 3, 5, 7, 11};
int main(void) { return primes[0] + primes[4] - 13; }
