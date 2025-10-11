//#LinkerDriver:gcc

#define ALIGNMENT 65536

struct __attribute__((aligned(ALIGNMENT))) S {
  short f[3];
};
struct S object;

int main() {
  void* ptr = &object;
  if ((unsigned long long)ptr & (ALIGNMENT - 1)) {
    __builtin_abort();
  }

  return 42;
}
