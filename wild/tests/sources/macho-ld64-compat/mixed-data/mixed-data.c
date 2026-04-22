// Mixed-data test: a writable global AND a libc call. ld64 emits
// both __DATA (for the writable global) and __DATA_CONST (for the
// __got slot that points at puts). Exercises the rename-to-const
// logic under compat mode: wild must keep __DATA writable while
// still producing a separate __DATA_CONST for the immutable GOT.
#include <stdio.h>
int counter = 7;
int main(void) {
  puts("mixed");
  return counter;
}
