static int return32(void) { return 32; }

int compute_value32(void) __attribute__((ifunc("resolve_compute_value32")));

static void* resolve_compute_value32(void) { return return32; }

int non_ifunc(void) { return 33; }
