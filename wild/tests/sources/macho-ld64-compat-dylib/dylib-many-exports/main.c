#include <dlfcn.h>
#include <stdio.h>
typedef int (*addfn)(int);
static int check(void* h, const char* name, int arg, int expect) {
  addfn f = (addfn)dlsym(h, name);
  if (!f) {
    fprintf(stderr, "dlsym %s: %s\n", name, dlerror());
    return 1;
  }
  int r = f(arg);
  if (r != expect) {
    fprintf(stderr, "%s(%d) = %d, want %d\n", name, arg, r, expect);
    return 1;
  }
  return 0;
}
int main(int argc, char** argv) {
  if (argc < 2) return 1;
  void* h = dlopen(argv[1], RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  int fail = 0;
  // Sample across the branching factor to catch trie mis-splits.
  fail |= check(h, "fn_aaaa", 10, 11);
  fail |= check(h, "fn_aabc", 10, 13);
  fail |= check(h, "fn_abcd", 10, 14);
  fail |= check(h, "fn_bbcc", 10, 16);
  fail |= check(h, "fn_cdef", 10, 20);
  fail |= check(h, "fn_dddd", 10, 21);
  fail |= check(h, "fn_eeee", 10, 22);
  int* ga = (int*)dlsym(h, "global_a");
  int* gb = (int*)dlsym(h, "global_b");
  int* gc = (int*)dlsym(h, "global_c");
  if (!ga || !gb || !gc) {
    fprintf(stderr, "globals missing\n");
    return 3;
  }
  if (*ga != 100 || *gb != 200 || *gc != 300) return 4;
  return fail;
}
