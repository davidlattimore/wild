//#AbstractConfig:default
//#Object:runtime.c

//#Config:custom-entry:default
//#LinkArgs:--entry=custom_entry
//#ExpectSym:custom_entry section=".text"
//#ExpectEntry:custom_entry
//#TestUpdateInPlace:true

//#Config:numeric-entry:default
//#LinkArgs:--entry=0x1234
//#ExpectEntry:0x1234
//#RunEnabled:false

#include "../common/runtime.h"

void custom_entry(void) {
  runtime_init();
  exit_syscall(42);
}
