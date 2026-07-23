//#Config:stack-size
//#LinkArgs: -z stack-size=1048576

//#Config:invalid-stack-size
//#LinkArgs:-z stack-size=3
//#ExpectError: stack size must be 16-byte aligned

extern char __data_end;
extern char __heap_base;

void _start(void) {
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;
  unsigned long stack_base = (data_end + 15) & ~15UL;

  if (heap_base != stack_base + 1048576) {
    __builtin_trap();
  }
}
