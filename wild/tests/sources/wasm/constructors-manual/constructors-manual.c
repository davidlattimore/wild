// When the program imports and calls __wasm_call_ctors, do not wrap the entry (wrapping would run
// constructors twice).

static int x;

__attribute__((constructor(101))) static void init(void) { x += 1; }

__attribute__((import_module("env"), import_name("__wasm_call_ctors"))) void __wasm_call_ctors(
    void);

void _start(void) {
  __wasm_call_ctors();
  if (x != 1) {
    __builtin_trap();
  }
}
