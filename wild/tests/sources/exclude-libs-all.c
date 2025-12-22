//#LinkArgs:-z now -Bshareable --exclude-libs ALL
//#Mode:dynamic
//#RunEnabled:false
//#Archive:exclude-libs-all-1.c
// We optimise away the GOT, but GNU ld doesn't.
//#DiffIgnore:section.got

// This symbol shouldn't end up in .dynsym. linker-diff checks this.
int foo(void);

int call_foo(void) {
  // This reference to foo should be optimised by the linker, since the symbol
  // is made hidden, so we know it cannot be overridden.
  return foo() + 2;
}
