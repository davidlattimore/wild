//#AbstractConfig:default
//#Object:ifunc_init.c
//#Object:runtime.c
//#RequiresGlibc:true
//#Arch: x86_64

//#Config:pie:default
//#CompArgs:-fpie
//#DiffIgnore:section.rela.plt.link

//#Config:no-pie:default
//#CompArgs:-fno-pie
//#DiffIgnore:section.rela.plt.link

#include "ifunc_init.h"
#include "init.h"
#include "runtime.h"

static int target_func(void) { return 42; }

int my_ifunc(void) __attribute__((ifunc("resolve_my_ifunc")));

static void* resolve_my_ifunc(void) { return target_func; }

void* ifunc_ptr_in_data = my_ifunc;

typedef int (*func_ptr)(void);

void _start(void) {
  runtime_init();

  int rv = init_ifuncs();
  if (rv != 0) {
    exit_syscall(rv);
  }

  func_ptr direct_ptr = my_ifunc;
  func_ptr data_ptr = (func_ptr)ifunc_ptr_in_data;

  if (direct_ptr != data_ptr) {
    exit_syscall(1);
  }

  if (direct_ptr() != 42) {
    exit_syscall(2);
  }

  if (data_ptr() != 42) {
    exit_syscall(3);
  }

  if (my_ifunc() != 42) {
    exit_syscall(4);
  }

  exit_syscall(42);
}
