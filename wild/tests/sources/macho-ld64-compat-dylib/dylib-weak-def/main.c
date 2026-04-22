#include <dlfcn.h>
#include <stdio.h>
typedef int (*fn1)(int);
int main(int argc, char** argv) {
  if (argc < 2) return 1;
  void* h = dlopen(argv[1], RTLD_NOW);
  if (!h) {
    fprintf(stderr, "dlopen: %s\n", dlerror());
    return 2;
  }
  fn1 caller = (fn1)dlsym(h, "caller");
  fn1 weak = (fn1)dlsym(h, "maybe_override");
  if (!caller || !weak) return 3;
  // Without interposition: weak(10) = 20, caller(10) = 21.
  if (weak(10) != 20) return 4;
  if (caller(10) != 21) return 5;
  return 0;
}
