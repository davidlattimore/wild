//#LinkerDriver:clang

static int order = 0;
static int first_val = 0, second_val = 0;

__attribute__((constructor(101))) void first(void) { first_val = ++order; }
__attribute__((constructor(102))) void second(void) { second_val = ++order; }

int main() {
  return (first_val == 1 && second_val == 2) ? 42 : first_val * 10 + second_val;
}
