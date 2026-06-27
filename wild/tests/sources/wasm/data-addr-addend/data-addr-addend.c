// Pointer to &a[1] should produce a MEMORY_ADDR relocation with a non-zero addend.
int a[2] = {1, 2};
int* p = &a[1];

void _start(void) {
  if (*p != 2) {
    __builtin_trap();
  }
}
