//#Config:with-entry
//#LinkArgs: --export=foo --export=add
//#Contains: foo.command_export
//#Contains: add.command_export
//#Contains: _start.command_export
//#ExpectSym: foo
//#ExpectSym: add
//#ExpectSym: _start

//#Config:no-entry
//#LinkArgs: --no-entry --export=foo
//#RunDynSym: foo
//#Contains: foo.command_export
//#DoesNotContain: _start.command_export
//#ExpectSym: foo
//#NoSym: _start

//#Config:export-ctors
//#LinkArgs: --export=__wasm_call_ctors --export=foo
//#RunEnabled: false
//#DoesNotContain: .command_export
//#ExpectSym: __wasm_call_ctors
//#ExpectSym: foo
//#ExpectSym: _start

static int x;

__attribute__((constructor(100))) static void init(void) { x = 42; }

void foo(void) {
  if (x != 42) {
    __builtin_trap();
  }
}

int add(int a, int b) { return a + b; }

void _start(void) {
  foo();
  if (add(1, 2) != 3) {
    __builtin_trap();
  }
}
