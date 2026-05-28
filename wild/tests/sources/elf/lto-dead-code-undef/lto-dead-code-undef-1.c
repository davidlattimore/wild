void bar(void);

int foo(int x) {
  // bar is undefined, but x is always 0, so the call to bar can be eliminated, allowing us to not
  // error despite the undefined symbol.
  if (x) {
    bar();
  }
  return 42;
}
