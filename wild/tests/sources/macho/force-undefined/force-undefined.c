//#Archive:lib.a:force-undefined1.c
//#LinkArgs:-u _forced_sym

// Tests -u flag: forces _forced_sym to be treated as undefined,
// which triggers loading the archive member that defines it.
// Without -u, the archive member wouldn't be loaded since nothing
// in the main object references forced_sym directly.
extern int forced_sym;
extern int get_value(void);
int main() { return get_value(); }
