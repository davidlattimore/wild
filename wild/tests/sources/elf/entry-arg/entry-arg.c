//#AbstractConfig:default
//#Object:runtime.c

//#Config:custom-entry:default
//#LinkArgs:--entry=custom_entry
//#ExpectSym:custom_entry section=".text"
//#TestUpdateInPlace:true

#include "runtime.h"

void custom_entry(void) {
  runtime_init();
  exit_syscall(42);
}
