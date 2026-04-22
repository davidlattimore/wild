// Runtime loader: dlopens the wild-built dylib and calls `add` via
// dlsym. Exit 0 on success; any mismatch returns a non-zero code.
#include <dlfcn.h>
#include <stdio.h>
typedef int (*add_fn)(int, int);
int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <dylib>\n", argv[0]);
    return 1;
  }
  void* h = dlopen(argv[1], RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  add_fn add = (add_fn)dlsym(h, "add");
  if (!add) {
    fprintf(stderr, "dlsym: %s\n", dlerror());
    return 3;
  }
  int r = add(40, 2);
  return r == 42 ? 0 : 4;
}
