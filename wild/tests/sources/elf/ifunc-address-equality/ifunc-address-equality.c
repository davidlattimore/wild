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

__attribute__((ifunc("resolve_foo"))) void foo(void);
static void real_foo(void) {}
static Func resolve_foo(void) { return real_foo; }

__attribute__((ifunc("resolve_bar"))) void bar(void);
static void real_bar(void) {}
static Func resolve_bar(void) { return real_bar; }

extern Func get_foo(void);
extern Func get_bar(void);

void _start(void) {
  runtime_init();

  int rv = init_ifuncs();
  if (rv != 0) {
    exit_syscall(rv);
  }

  Func direct_foo = foo;
  Func got_foo = get_foo();

  if (direct_foo != got_foo) {
    exit_syscall(1);
  }

  Func direct_bar = bar;
  Func got_bar = get_bar();

  if (direct_bar != got_bar) {
    exit_syscall(2);
  }

  if (direct_foo == direct_bar) {
    exit_syscall(3);
  }

  direct_foo();
  got_foo();
  direct_bar();
  got_bar();

  exit_syscall(42);
}
