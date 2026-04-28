int get_3(void);

__attribute__((aligned(32), section(".text.align32"))) int get_3_aligned(void) {
  return get_3();
}

int call_get_3(void) { return get_3_aligned(); }
