//#AbstractConfig:default
//#Object:ifunc-address-equality-1.c:-fPIC
//#Object:ifunc_init.c
//#Object:runtime.c
//#DiffIgnore:section.rela.plt.link
//#RequiresGlibc:true
//#Arch:x86_64

//#Config:no-pie:default
//#CompArgs:-fno-pie

#include "ifunc_init.h"
#include "runtime.h"

typedef void (*Func)(void);

// foo and bar are defined in ifunc-address-equality-1.c (compiled -fPIC).
// This file has no direct (non-GOT) references to them, so the resolved
// function address is canonical and data pointers must match it via IRELATIVE.
extern void foo(void);
extern void bar(void);

extern Func get_foo(void);
extern Func get_bar(void);
extern Func foo_data_ptr;
extern Func bar_data_ptr;

void _start(void) {
  runtime_init();

  int rv = init_ifuncs();
  if (rv != 0) {
    exit_syscall(rv);
  }

  Func got_foo = get_foo();
  Func got_bar = get_bar();

  if (got_foo == got_bar) {
    exit_syscall(1);
  }

  if (got_foo != foo_data_ptr) {
    exit_syscall(2);
  }

  if (got_bar != bar_data_ptr) {
    exit_syscall(3);
  }

  got_foo();
  got_bar();
  foo_data_ptr();
  bar_data_ptr();

  exit_syscall(42);
}