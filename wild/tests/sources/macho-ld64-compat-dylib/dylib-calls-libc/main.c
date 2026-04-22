#include <dlfcn.h>
typedef int (*mf)(const char*);
int main(int argc, char** argv) {
  if (argc < 2) return 1;
  void* h = dlopen(argv[1], RTLD_NOW);
  if (!h) return 2;
  mf measure = (mf)dlsym(h, "measure");
  if (!measure) return 3;
  return measure("hello") == 5 ? 0 : 4;
}
