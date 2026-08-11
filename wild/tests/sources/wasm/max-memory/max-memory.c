//#Config:default
//#LinkArgs: --initial-memory=131072 --max-memory=196608 -z stack-size=65536 --stack-first
//#CompArgs: -DGROW_ONCE

//#Config:max
//#LinkArgs: --max-memory=4294967296 -z stack-size=65536 --stack-first

//#Config:unaligned
//#LinkArgs: --max-memory=1000
//#ExpectError: maximum memory must be aligned

//#Config:too-small
//#LinkArgs: --max-memory=65536 -z stack-size=1048576 --stack-first
//#ExpectError: maximum memory too small

//#Config:too-large
//#LinkArgs: --max-memory=4295032832
//#ExpectError: maximum memory too large

void _start(void) {
  unsigned long first = __builtin_wasm_memory_grow(0, 1);
  if (first == (unsigned long)-1) {
    __builtin_trap();
  }
#ifdef GROW_ONCE
  unsigned long second = __builtin_wasm_memory_grow(0, 1);
  // The initial memory is 2 pages and the max is 3 pages, so the second grow should fail.
  if (second != (unsigned long)-1) {
    __builtin_trap();
  }
#endif
}
