//#LinkerDriver:clang
// Test that __attribute__((constructor)) functions run before main.
static int init_val = 0;

__attribute__((constructor)) void my_init(void) { init_val = 42; }

int main() { return init_val; }
