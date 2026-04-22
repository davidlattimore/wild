// Weak definition — ld64 marks the symbol N_WEAK_DEF in the nlist and
// its entry in the exports trie gets EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION.
// Catches compat-mode regressions where wild's symtab emission or
// exports-trie builder doesn't carry the weak flag through.
__attribute__((weak)) int fallback(int x) { return x * 2; }
int main(void) { return fallback(21) - 42; }
