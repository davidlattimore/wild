static int ifunc1_impl(void) { return 10; }

int ifunc1(void) __attribute__((ifunc("resolve_ifunc1")));

static void* resolve_ifunc1(void) { return ifunc1_impl; }
