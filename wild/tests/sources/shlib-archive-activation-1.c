int f1a(void) { return 50; }

int f1(void) { return f1a(); }

int f2b(void);

int f2(void) {
  // This reference causes the archive entry shlib-archive-activation-2 to be
  // loaded.
  return f2b();
}
