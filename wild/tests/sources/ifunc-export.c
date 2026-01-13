//#LinkerDriver:gcc
//#LinkArgs:-no-pie -Wl,-z,now
//#Shared:ifunc-export-1.c:-fPIC
//#RequiresGlibc:true
//#Arch:x86_64
//#DiffIgnore:section.rodata
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.data
//#DiffIgnore:dynsym.foo.section

typedef void (*Func)(void);
static int foo_called = 0;
static void real_foo(void) { foo_called = 1; }
static Func resolve_foo(void) { return real_foo; }
__attribute__((ifunc("resolve_foo"))) void foo(void);
extern Func get_foo(void);

int main() {
  Func direct_foo = foo;
  Func got_foo = get_foo();

  if (direct_foo != got_foo) {
    return 1;
  }

  foo_called = 0;
  direct_foo();
  if (foo_called != 1) {
    return 2;
  }

  foo_called = 0;
  got_foo();
  if (foo_called != 1) {
    return 3;
  }

  return 42;
}
