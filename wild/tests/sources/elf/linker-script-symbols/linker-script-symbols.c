//#Config:default
//#AugmentLinkerScript:script.ld
//#Object:runtime.c

#include "../common/runtime.h"

int value1 = 100;
int value2 = 200;

extern int value1a;
extern int value2a;

int foo(void) { return 9; }
int foo_alias(void);

void _start(void) {
  runtime_init();

  if (foo_alias() != 9) {
    exit_syscall(9);
  }

  if (value1a != 100) {
    exit_syscall(10);
  }

  if (value2 != 200) {
    exit_syscall(11);
  }

  exit_syscall(42);
}
