// __attribute__((used)) sets WASM_SYM_NO_STRIP so the function is a GC root even when nothing calls
// it.

//#ExpectSection: name
//#Contains: gc_nostrip_rooted_fn
//#DoesNotContain: gc_nostrip_dead_fn

__attribute__((used)) void gc_nostrip_rooted_fn(void) {}

void gc_nostrip_dead_fn(void) {}

void _start(void) {}
