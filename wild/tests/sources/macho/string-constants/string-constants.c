//#Contains:Hello World

// Test that string literals are present and the binary links correctly.
const char* get_str1(void) { return "Hello World"; }
const char* get_str2(void) { return "Hello World"; }

int main() {
  // Whether the linker merges identical strings is an optimisation choice.
  // We just verify the values are correct.
  const char* a = get_str1();
  const char* b = get_str2();
  if (a[0] != 'H') return 1;
  if (b[0] != 'H') return 2;
  return 42;
}
