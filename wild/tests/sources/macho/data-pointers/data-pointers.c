//#Object:data-pointers1.c

// Tests that data pointers (function pointers and data addresses) in the
// DATA section are correctly rebased for ASLR.

extern int values[4];
extern int (*get_fn(void))(void);

int main() {
  // Check data array values
  if (values[0] != 10) return 1;
  if (values[1] != 20) return 2;

  // Check function pointer from another object
  int (*fn)(void) = get_fn();
  return fn();
}
