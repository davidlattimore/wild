//#Config:stack-size
//#CompArgs:-DNO_STACK_FIRST
//#LinkArgs: -z stack-size=1048576 --no-stack-first
//#RequiresLinkerFlags: --no-stack-first

//#Config:stack-first
//#LinkArgs: -z stack-size=1048576 --stack-first

//#Config:invalid-stack-size
//#LinkArgs:-z stack-size=3
//#ExpectError: stack size must be 16-byte aligned

extern char __data_end;
extern char __heap_base;

void _start(void) {
  unsigned long data_end = (unsigned long)&__data_end;
  unsigned long heap_base = (unsigned long)&__heap_base;

#ifdef NO_STACK_FIRST
  unsigned long stack_base = (data_end + 15) & ~15UL;
  if (heap_base != stack_base + 1048576) {
    __builtin_trap();
  }
#else
  if (heap_base < 1048576 || data_end < 1048576) {
    __builtin_trap();
  }
#endif
}
