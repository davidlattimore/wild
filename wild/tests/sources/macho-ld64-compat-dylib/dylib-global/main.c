#include <dlfcn.h>
#include <stdio.h>
typedef int (*bump_fn)(void);
int main(int argc, char** argv) {
  if (argc < 2) return 1;
  void* h = dlopen(argv[1], RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  int* c = (int*)dlsym(h, "counter");
  bump_fn bump = (bump_fn)dlsym(h, "bump");
  if (!c || !bump) {
    fprintf(stderr, "dlsym failed\n");
    return 3;
  }
  if (*c != 7) return 4;
  int r = bump();
  if (r != 8 || *c != 8) return 5;
  return 0;
}
