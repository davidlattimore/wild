// Varargs libc call — exercises a second import (`_printf`) through the
// chained-fixups table alongside `_puts`. Catches off-by-one or ordering
// bugs in `write_chained_fixups_header`'s imports / symbols-pool layout
// that a single-import fixture like `hello-puts` wouldn't surface.
#include <stdio.h>
int main(int argc, char** argv) {
  printf("argc=%d\n", argc);
  puts("done");
  return 0;
}
