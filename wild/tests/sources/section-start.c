//#Config:section-start
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now -Wl,--section-start=.foo=0x1000000 -no-pie
//#ExpectSym:foo address=0x1000000
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:section.rodata.alignment
//#DiffIgnore:section.data
//#DiffIgnore:section.sdata

#include <stdio.h>

__attribute__((section(".foo"))) void foo() { printf("foo\n"); }

int main() {
  foo();

  return 42;
}
