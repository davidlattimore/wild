//#LinkerScript:linker-script-section-start.ld
//#LinkerDriver:gcc
//#LinkArgs:-no-pie
//#ExpectSym:foo address=0x1000000
//#DiffIgnore:section.rodata.alignment
//#DiffIgnore:section.data
//#DiffIgnore:section.sdata
//#SkipArch:loongarch64

/* BFD rejects similar absolute-placement code on loongarch with relocation truncation. */

#include <stdio.h>

__attribute__((section(".foo"))) void foo() { printf("foo\n"); }

int main() {
  foo();
  return 42;
}
