//#Config:no-entry
//#LinkArgs: --no-entry --export=foo
//#RunEnabled:false
//#Contains: foo

//#Config:custom-entry
//#LinkArgs: --entry=custom_entry
//#RunEnabled:false
//#Contains: custom_entry

//#Config:entry-then-no-entry
//#LinkArgs: --entry=custom_entry --no-entry --export=foo
//#RunEnabled:false
//#Contains: foo

int foo(void) { return 7; }

void custom_entry(void) {}

void _start(void) {
  if (foo() != 7) {
    __builtin_trap();
  }
}
