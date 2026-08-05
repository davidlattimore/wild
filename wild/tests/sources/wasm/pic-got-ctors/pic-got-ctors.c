//#CompArgs:-fPIC

static int x;

__attribute__((constructor(100))) static void init(void) { x = 42; }

typedef void (*VoidFn)(void);

extern void __wasm_call_ctors(void);

static VoidFn get_ctors(void) { return __wasm_call_ctors; }

void _start(void) {
  get_ctors()();
  if (x != 42) {
    __builtin_trap();
  }
}
