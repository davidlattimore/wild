#include <unistd.h>

int foo(void) { return 42; }

int bar(void) {
  // Call something that will force us to link against libc. We don't actually
  // run this code.
  if (read(0, NULL, 0) == 0) {
    return 0;
  } else {
    return 1;
  }
}
