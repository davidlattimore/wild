extern int repeated_data;

__attribute__((section("unique_function"), noinline)) int singleton_function(void) {
  return repeated_data + 5;
}
