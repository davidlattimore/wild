// Static function test: `static` gives the function internal linkage,
// so it does NOT end up in LC_DYLD_EXPORTS_TRIE (external exports
// only) but it DOES end up in LC_FUNCTION_STARTS. Catches bugs where
// the compat-mode exporter over-publishes locals or the
// function-starts emitter under-includes them.
static int helper(int x) { return x + 1; }
int main(void) { return helper(41) - 42; }
