// Regression test for `___dso_handle` synthesis.
//
// `___dso_handle` is a magic symbol the linker injects: a pointer to
// the mach_header of the current image. C/C++ runtimes use it with
// `__cxa_atexit` to register destructors. ld64 synthesizes it
// automatically; wild currently errors "undefined symbol: ___dso_handle".
//
// Triggers in the wild whenever a C/C++ object file registers a
// destructor via `__attribute__((destructor))` or a C++ translation
// unit with non-trivial global destructors — very common in
// wasm-opt, cxx, link-cplusplus (seen in substrate-wasm-builder).
extern void* __dso_handle;
__attribute__((destructor)) static void cleanup(void) {}
int main(void) { return __dso_handle ? 42 : 1; }
