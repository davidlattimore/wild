//#Object:data-end-heap-base2.c
//#LinkArgs:--no-stack-first
//#RequiresLinkerFlags: --no-stack-first

extern char __global_base;
extern char __data_end;
extern char __heap_base;
extern int y;
extern unsigned long global_base_from_other_tu(void);
extern unsigned long data_end_from_other_tu(void);
extern unsigned long heap_base_from_other_tu(void);

int x = 1;

void _start(void) {
  unsigned long global_base = (unsigned long)&__global_base;
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;
  unsigned long global_base2 = global_base_from_other_tu();
  unsigned long data_end2 = data_end_from_other_tu();
  unsigned long heap_base2 = heap_base_from_other_tu();

  // Without --stack-first, static data starts at LINKER_MEMORY_BASE (1024).
  if (global_base != 1024) {
    __builtin_trap();
  }
  // Static data starts at __global_base. exact end can differ by linker packing.
  if (data_end <= global_base || heap_base < data_end + 64 * 1024) {
    __builtin_trap();
  }
  if (global_base2 != global_base || data_end2 != data_end || heap_base2 != heap_base) {
    __builtin_trap();
  }
  if (x != 1 || y != 2) {
    __builtin_trap();
  }
}
