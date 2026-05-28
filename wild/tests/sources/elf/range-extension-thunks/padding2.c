int padding2(void) { __asm__ __volatile__(".fill 67108864, 1, 0\n"); }

int foo2(void) { return 2; }
int bar2(void) { return 12; }
