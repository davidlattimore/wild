//#Arch: x86_64
//#ReferenceLinkers:bfd,lld
//#Object:runtime.c
//#Relocatable:partial-link-singletons-1.c,partial-link-singletons-2.c

#include "../common/runtime.h"

int singleton_function(void);
extern int unique_data;
extern int unique_bss;

void _start(void) {
  runtime_init();

  if (singleton_function() != 47) {
    exit_syscall(1);
  }
  if (unique_data != 17) {
    exit_syscall(2);
  }
  if (unique_bss != 0) {
    exit_syscall(3);
  }
  unique_bss = 23;
  if (unique_bss != 23) {
    exit_syscall(4);
  }
  exit_syscall(42);
}
