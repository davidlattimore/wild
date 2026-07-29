//#CompArgs:-fPIC
// PIC `GLOBAL_INDEX` / GOT.mem against linker-defined data (`__data_end`, `__heap_base`).

extern char __data_end;
extern char __heap_base;

void _start(void) {
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;
  if (data_end < 1024) {
    __builtin_trap();
  }
  if (heap_base < data_end) {
    __builtin_trap();
  }
}
