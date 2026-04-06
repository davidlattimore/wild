// Test that uninitialised globals are zero-filled (BSS).
int uninit_global;
static int uninit_static;

int main() {
  if (uninit_global != 0) return 1;
  if (uninit_static != 0) return 2;
  return 42;
}
