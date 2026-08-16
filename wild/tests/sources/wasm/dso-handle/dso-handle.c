//#AbstractConfig:base
//#Object:dso-handle2.c

//#Config:default:base

//#Config:pic:base
//#CompArgs: -fPIC

//#Config:stack-first:base
//#LinkArgs: -z stack-size=1048576 --stack-first

extern char __dso_handle;
extern unsigned long global_base_from_other_tu(void);

void _start(void) {
  unsigned long dso = (unsigned long)&__dso_handle;
  unsigned long global_base = global_base_from_other_tu();

  // wasm-ld sets __dso_handle to the start of static data (__global_base).
  if (dso != global_base) {
    __builtin_trap();
  }
}
