int g1 = 1;
int g2 = 2;

int add(int x, int y) { return x + y; }

int inc(int x) { return x + 1; }

void _start(void) {
  if (g1 != 1 || g2 != 2) {
    __builtin_trap();
  }
  if (add(g1, g2) != 3) {
    __builtin_trap();
  }
  if (inc(g1) != 2) {
    __builtin_trap();
  }
}
