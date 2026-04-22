// Minimal dylib with a single exported function. Tests structural
// emission of LC_ID_DYLIB, LC_LOAD_DYLIB (libSystem), LC_DYLD_EXPORTS_TRIE
// containing the exported symbol, and the dylib's codesign blob.
int add(int a, int b) { return a + b; }
