//#Object:data-end-heap-base2.c

extern char __data_end;
extern char __heap_base;
extern int y;

int x = 1;

void _start(void) {
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;

  if (data_end <= 1024) {
    __builtin_trap();
  }
  if (heap_base < data_end + 64 * 1024) {
    __builtin_trap();
  }
  if (x != 1 || y != 2) {
    __builtin_trap();
  }
}
