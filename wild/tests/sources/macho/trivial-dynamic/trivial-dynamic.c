//#LinkerDriver:clang
//#Shared:trivial-dynamic1.c

// Tests basic dynamic linking with a shared library.
extern int dyn_func(void);
int main() { return dyn_func(); }
