// Tests that on Mach-O, archives only satisfy undefined references.
// A weak definition in an object is NOT overridden by a strong one in an
// archive.
//#Object:weak-override-archive1.c
//#Archive:weak-override-archive2.c

__attribute__((weak)) int foo(void) { return 1; }
int bar(void);

int main() {
  // foo stays 1 (weak def in this TU; archive not pulled in since foo is
  // defined) bar is 10 (from companion object)
  if (foo() != 1) return foo();
  if (bar() != 10) return bar();
  return 42;
}
