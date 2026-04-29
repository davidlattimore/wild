int get_3(void) { return 3; }

int get_3_aligned(void);

// Call from a default-aligned function to a 32-byte aligned function then back
// to a default aligned function.
int foo3(void) { return get_3_aligned(); }

int bar3(void) { return 13; }

int shared1(void);

int call_shared1_from_far1(void) { return shared1(); }

int ifunc1(void);

int call_ifunc1_from_far1(void) { return ifunc1(); }

// ifunc2 differs from ifunc1 in that it (the resolver function) is defined
// here, which is a long way from the PLT that calls will go via.
static int ifunc2_impl(void) { return 99; }

int ifunc2(void) __attribute__((ifunc("resolve_ifunc2")));

static void* resolve_ifunc2(void) { return ifunc2_impl; }

int call_ifunc2_from_far1(void) { return ifunc2(); }
