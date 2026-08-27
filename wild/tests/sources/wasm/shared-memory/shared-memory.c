//#Config:default
//#LinkArgs: --shared-memory --max-memory=131072
//#CompArgs: -matomics
//#ExpectSharedMemory: true
//#Contains: atomics
//#Contains: bulk-memory

//#Config:no-max
//#LinkArgs: --shared-memory
//#CompArgs: -matomics
//#ExpectSharedMemory: true

//#Config:missing-atomics
//#LinkArgs: --shared-memory
//#ExpectError: 'atomics' feature must be used in order to use shared memory

//#Config:unaligned
//#LinkArgs: --shared-memory --max-memory=100000
//#CompArgs: -matomics
//#ExpectError: maximum memory must be aligned

int value = 42;

void _start(void) {
  if (value != 42) {
    __builtin_trap();
  }
}
