//#AbstractConfig:default
//#Object:runtime.c

//#Config:stack-size:default
//#LinkArgs:-z stack-size=0x1000 -z now
//#DiffIgnore:section.note.gnu.property

#include "runtime.h"

void _start() {
  runtime_init();
  exit_syscall(42);
}
