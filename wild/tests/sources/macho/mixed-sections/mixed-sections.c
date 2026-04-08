// Tests correct handling of multiple section types together:
// __text, __const, __cstring, __data, __bss, __got.
// This exercises the section header generation for the DATA segment.
//#LinkerDriver:clang
//#Object:mixed-sections1.c

#include <string.h>

extern int mutable_val;
extern const int readonly_table[];
void bump(void);
const char* get_name(void);

int main() {
  // __data: mutable global
  bump();
  if (mutable_val != 11) return 1;

  // __const: read-only table
  if (readonly_table[0] + readonly_table[3] != 104) return 2;

  // __cstring: string literal from another TU
  if (strcmp(get_name(), "hello") != 0) return 3;

  return 42;
}
