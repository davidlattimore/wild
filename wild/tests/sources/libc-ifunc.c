//#CompArgs:-fPIC -g
//#LinkerDriver:gcc
//#LinkArgs:-pie -Wl,-z,now
//#DiffIgnore:section.rodata
// GNU ld emits an extra IRELATIVE relocation, while LLD and Wild instead point
// to the PLT entry. So we need to diff against lld.
//#EnableLinker:lld
//#RequiresGlibc:true

int foo() { return 42; }

int bar() __attribute__((ifunc("resolve_bar")));

void *resolve_bar() { return foo; }

typedef int (*int_f_ptr_t)(void);

int_f_ptr_t bar2 = bar;

int main() {
  if (bar() != 42) {
    return bar();
  }

  return bar2();
}
