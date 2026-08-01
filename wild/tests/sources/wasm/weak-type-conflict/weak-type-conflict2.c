__attribute__((weak)) void conflict_fn(void);

void other(void) {
  if (conflict_fn) {
    conflict_fn();
  }
}
