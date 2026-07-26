//#Config:no-entry
//#LinkArgs: --no-entry --export=foo
//#RunEnabled:false
//#ExpectSym: foo
//#ExpectSym: memory
//#NoSym: _start
//#NoSym: custom_entry

//#Config:custom-entry
//#LinkArgs: --entry=custom_entry
//#RunEnabled:false
//#ExpectSym: custom_entry
//#ExpectSym: memory
//#NoSym: _start
//#NoSym: foo

//#Config:entry-then-no-entry
//#LinkArgs: --entry=custom_entry --no-entry --export=foo
//#RunEnabled:false
//#ExpectSym: foo
//#ExpectSym: memory
//#NoSym: _start
//#NoSym: custom_entry

//#Config:missing-entry
//#LinkArgs: --entry=does_not_exist
//#ExpectError: entry symbol not defined

int foo(void) { return 7; }

void custom_entry(void) {}

void _start(void) {
  if (foo() != 7) {
    __builtin_trap();
  }
}
