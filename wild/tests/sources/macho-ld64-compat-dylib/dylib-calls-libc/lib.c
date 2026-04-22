// Dylib that itself imports from libSystem — forces wild to emit
// __stubs / __got / LC_DYLD_CHAINED_FIXUPS imports inside a dylib,
// not just an exe. Catches regressions in the dylib's bind/rebase
// table that the trivial exe path would miss.
#include <string.h>
int measure(const char* s) { return (int)strlen(s); }
