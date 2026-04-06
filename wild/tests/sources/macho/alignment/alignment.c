// Test that the linker respects large alignment requirements.
struct __attribute__((aligned(16384))) S {
  int x;
};
struct S obj = {.x = 42};

int main() {
  if ((unsigned long long)&obj & 0x3FFF) return 1;
  return obj.x;
}
