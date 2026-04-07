//#Archive:lib.a:weak-fns-archive1.c

// Tests that an archive member is loaded to resolve an undefined symbol,
// even when the main object has other weak definitions.
int __attribute__((weak)) unused_weak(void) { return 0; }
int get_value(void);
int main() { return get_value() + unused_weak(); }
