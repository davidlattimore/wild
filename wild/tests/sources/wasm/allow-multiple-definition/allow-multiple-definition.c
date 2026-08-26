//#Config:dup
//#ReferenceLinkers:
//#Object:allow-multiple-definition2.c
//#ExpectError:Duplicate symbols

//#Config:allow-then-disallow
//#ReferenceLinkers:
//#Object:allow-multiple-definition2.c
//#LinkArgs: --allow-multiple-definition --no-allow-multiple-definition
//#ExpectError:Duplicate symbols

//#Config:allow
//#Object:allow-multiple-definition2.c
//#LinkArgs: --allow-multiple-definition

//#Config:z-muldefs
//#Object:allow-multiple-definition2.c
//#LinkArgs: -z muldefs

int foo(void) { return 0; }

void _start(void) {
  if (foo() != 0) {
    __builtin_trap();
  }
}
