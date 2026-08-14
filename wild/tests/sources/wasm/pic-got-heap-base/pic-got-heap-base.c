//#CompArgs:-fPIC
// PIC `GLOBAL_INDEX` / GOT.mem against linker-defined data.

extern char __global_base;
extern char __data_end;
extern char __heap_base;

void _start(void) {
  unsigned long global_base = (unsigned long)&__global_base;
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;
  if (global_base < 1024 || global_base > data_end) {
    __builtin_trap();
  }
  if (data_end < 1024) {
    __builtin_trap();
  }
  if (heap_base < data_end) {
    __builtin_trap();
  }
}
