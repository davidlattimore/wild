//#AbstractConfig:default
//#Object:runtime.c
//#Object:ptr_black_box.c
//#ReferenceLinkers:lld
//#DiffMatchAny:true
//#ExpectSym:__dso_handle
//#NoDynSym:__dso_handle

//#Config:exec:default
//#LinkArgs:-z now

//#Config:shared:default
//#LinkArgs:-shared -z now
//#CompArgs:-fPIC -DSHARED
//#RunEnabled:false

#include "../common/ptr_black_box.h"
#include "../common/runtime.h"

extern char __dso_handle;
extern char __ehdr_start;

#ifdef SHARED
void* get_dso_handle(void) { return &__dso_handle; }
#else
void _start(void) {
  runtime_init();

  if (ptr_to_int(&__dso_handle) == 0) {
    exit_syscall(10);
  }

  if (&__dso_handle != &__ehdr_start) {
    exit_syscall(11);
  }

  exit_syscall(42);
}
#endif
