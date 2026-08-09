// InitFuncs (from __attribute__((constructor))) roots ctors even when they are not reachable from
// _start's call graph alone. Edges from the ctor keep helpers.

//#ExpectSection: name
//#Contains: gc_only_from_ctor
//#DoesNotContain: gc_initfuncs_dead_fn

static int x;

static void gc_only_from_ctor(void) { x = 7; }

__attribute__((constructor(100))) static void gc_init_ctor(void) { gc_only_from_ctor(); }

void gc_initfuncs_dead_fn(void) {}

void _start(void) {
  if (x != 7) {
    __builtin_trap();
  }
}
