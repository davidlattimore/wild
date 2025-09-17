extern int compute_value(void);

int resolve_count = 0;

static int return10(void) { return 10; }

int compute_value10(void) __attribute__((ifunc("resolve_compute_value10")));

static void* resolve_compute_value10(void) {
  resolve_count++;
  return return10;
}

static int return32(void) { return 32; }

int compute_value32(void) __attribute__((ifunc("resolve_compute_value32")));

static void* resolve_compute_value32(void) {
  resolve_count++;
  return return32;
}

static int unused(void) { return 20; }

int compute_unused(void) __attribute__((ifunc("resolve_compute_unused")));

static void* resolve_compute_unused(void) { return unused; }
