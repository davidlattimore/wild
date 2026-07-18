//#Config:export-functions
//#LinkArgs: --export=foo
//#Contains: foo
// TODO(wasm): verify that `not_exported` is actually not exported

//#Config:missing-export
//#LinkArgs: --export does_not_exist
//#ExpectError: symbol exported via --export not found: does_not_exist

int foo(void) { return 42; }

void not_exported(void) {}

void _start(void) {
  if (foo() != 42) {
    __builtin_trap();
  }
}
