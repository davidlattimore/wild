//#AbstractConfig:default
//#Object:runtime.c
//#Object:ptr_black_box.c
//#EnableLinker:lld

//#Config:no-pie:default
//#LinkArgs:-no-pie -znow

//#Config:pie:default

//#Config:dynamic:default
//#Mode:dynamic
//#Shared:force-dynamic-linking.c
//#DiffIgnore:.dynamic.DT_NEEDED

#include "ptr_black_box.h"
#include "runtime.h"

extern char __executable_start;

void _start(void) {
  runtime_init();

  if (ptr_to_int(&__executable_start) > ptr_to_int(&_start)) {
    exit_syscall(10);
  }

  if (ptr_to_int(&__executable_start) == 0) {
    exit_syscall(11);
  }

  exit_syscall(42);
}
