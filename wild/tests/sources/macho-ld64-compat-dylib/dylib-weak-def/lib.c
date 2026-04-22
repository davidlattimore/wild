// Weak-def exports: ld64 flags these with
// EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION in the trie and wild must
// route their callers through __stubs→__got (see weak-sym compat
// fixture). For a dylib the additional expectation is that the
// weak-def flag propagates into the exports trie so dyld knows to
// participate in coalescing.
__attribute__((weak)) int maybe_override(int x) { return x * 2; }
int caller(int x) { return maybe_override(x) + 1; }
