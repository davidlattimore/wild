// `__attribute__((visibility("hidden")))` → symbol is external within
// the object but not exported from the final image. ld64 drops it from
// `LC_DYLD_EXPORTS_TRIE` and emits it as local in the symtab. Catches
// compat-mode bugs where wild's `is_symbol_external` check doesn't
// honour the hidden attribute.
__attribute__((visibility("hidden"))) int inner(void) { return 7; }
int main(void) { return inner() - 7; }
