// Multiple cstring literals — exercises `__cstring` merging. ld64
// deduplicates identical literals; wild uses merged-string resolution
// in `write_merged_strings_macho`. With three literals plus a printf
// call, the cstring pool has enough content to surface ordering or
// merge-target divergences that single-string fixtures miss.
#include <stdio.h>
int main(void) {
  puts("alpha");
  puts("alpha");
  puts("beta");
  printf("%s\n", "alpha");
  return 0;
}
