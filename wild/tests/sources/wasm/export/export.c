//#Config:export-functions
//#LinkArgs: --export=foo
//#ExpectSection: name
//#ExpectSym: foo
//#ExpectSym: _start
//#ExpectSym: memory
//#NoSym: not_exported

//#Config:missing-export
//#LinkArgs: --export does_not_exist
//#ExpectError: symbol exported via --export not found: does_not_exist

//#Config:export-if-defined
//#LinkArgs: --export-if-defined=not_exported --export-if-defined=does_not_exist
//#ExpectSym: not_exported
//#NoSym: does_not_exist

int foo(void) { return 42; }

void not_exported(void) {}

void _start(void) {
  if (foo() != 42) {
    __builtin_trap();
  }
}
