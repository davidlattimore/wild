//#LinkArgs: -z stack-size=1048576 --stack-first

int payload[8] = {1, 2, 3, 4, 5, 6, 7, 8};

extern char __global_base;
extern char __data_end;
extern char __heap_base;

void _start(void) {
  unsigned long global_base = (unsigned long)&__global_base;
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;
  unsigned long stack_size = 1048576;

  // With --stack-first, static data starts at stack_size.
  if (global_base != stack_size) {
    __builtin_trap();
  }
  if (data_end <= global_base) {
    __builtin_trap();
  }
  // Heap immediately follows data (at most 16-byte alignment padding).
  if (heap_base < data_end || heap_base > data_end + 16) {
    __builtin_trap();
  }
  // payload must be reachable inside the data region.
  if ((unsigned long)&payload[0] < stack_size) {
    __builtin_trap();
  }
  if (payload[0] != 1 || payload[7] != 8) {
    __builtin_trap();
  }
}
