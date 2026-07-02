// TODO(wasm): Enable running once crt1 is linked in tests. Without crt, wasm-ld leaves these as
// imports so the reference output cannot be instantiated. Wild already synthesizes empty
// definitions.
//#RunEnabled: false
//#ExpectSection: Code

__attribute__((import_module("env"), import_name("__wasm_call_ctors"))) void __wasm_call_ctors(
    void);
__attribute__((import_module("env"), import_name("__wasm_call_dtors"))) void __wasm_call_dtors(
    void);

void _start(void) {
  __wasm_call_ctors();
  __wasm_call_dtors();
}
