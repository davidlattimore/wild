//#Config:default
//#LinkArgs: --initial-memory=20971520 -z stack-size=65536 --stack-first
//#CompArgs: -DEXPECTED_HEAP_END=20971520UL

//#Config:equals-form
//#LinkArgs: --initial-memory=131072 -z stack-size=65536 --stack-first
//#CompArgs: -DEXPECTED_HEAP_END=131072UL

//#Config:too-small
//#LinkArgs: --initial-memory=65536 -z stack-size=1048576 --stack-first
//#CompArgs: -DEXPECTED_HEAP_END=0
//#ExpectError: initial memory too small

//#Config:unaligned
//#LinkArgs: --initial-memory=1000
//#CompArgs: -DEXPECTED_HEAP_END=0
//#ExpectError: initial memory must be aligned

//#Config:max
//#LinkArgs: --initial-memory=4294967296
//#CompArgs: -DEXPECTED_HEAP_END=0
// wasm-ld allows --initial-memory=2^32 but it makes `__heap_end` wrap around to 0, so Wild rejects
// it
//#ReferenceLinkers:
//#ExpectError: initial memory too large

extern char __heap_end;

void _start(void) {
  unsigned long heap_end = (unsigned long)&__heap_end;
  if (heap_end != EXPECTED_HEAP_END) {
    __builtin_trap();
  }
}
