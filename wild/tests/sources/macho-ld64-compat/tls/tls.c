// Thread-local storage — exercises the `__thread_vars` / `__thread_data`
// pair that wild routes through `PREINIT_ARRAY` / `TDATA`. ld64 emits a
// `__DATA,__thread_vars` section with S_THREAD_LOCAL_VARIABLES flag
// pointing at `__DATA,__thread_data` entries (S_THREAD_LOCAL_REGULAR).
// Hardest fixture in this batch: the full TLV descriptor machinery
// plus the dylib import for `tlv_get_addr` has to match ld64's layout.
_Thread_local int counter = 13;
int main(void) {
  counter += 29;
  return counter - 42;
}
