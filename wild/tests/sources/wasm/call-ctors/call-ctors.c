// TODO(wasm): Enable running once crt1 is linked in tests. Without crt, the dtor remains an import
// so the output cannot be instantiated.
//#RunEnabled: false
//#ExpectSection: Code
//#ExpectSection: name
//#ExpectFuncImport: env/__wasm_call_dtors=1
//#ExpectFuncImportCount: 1
//#Contains: __wasm_call_ctors
//#Contains: __wasm_call_dtors

__attribute__((import_module("env"), import_name("__wasm_call_ctors"))) void __wasm_call_ctors(
    void);
__attribute__((import_module("env"), import_name("__wasm_call_dtors"))) void __wasm_call_dtors(
    void);

void _start(void) {
  __wasm_call_ctors();
  __wasm_call_dtors();
}
