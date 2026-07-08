//#Object:data-end-heap-base2.c

extern char __data_end;
extern char __heap_base;
extern int y;
extern unsigned long data_end_from_other_tu(void);
extern unsigned long heap_base_from_other_tu(void);

int x = 1;

void _start(void) {
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;
  unsigned long data_end2 = data_end_from_other_tu();
  unsigned long heap_base2 = heap_base_from_other_tu();

  // Static data starts above LINKER_MEMORY_BASE. exact end can differ by linker packing.
  if (data_end <= 1024 || heap_base < data_end + 64 * 1024) {
    __builtin_trap();
  }
  if (data_end2 != data_end || heap_base2 != heap_base) {
    __builtin_trap();
  }
  if (x != 1 || y != 2) {
    __builtin_trap();
  }
}
