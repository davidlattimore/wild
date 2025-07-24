//#Object:runtime.c
//#EnableLinker:lld
//#Mode:dynamic
//#CompSoArgs:-fPIC
//#LinkArgs:-z now
//#Shared:copy-relocations-2.c
//#Object:copy-relocations-3.c:-fPIC
// We're linking different .so files, so this is expected.
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:dynsym.w2.section

#include "runtime.h"

// These two symbols are at the same address in the shared object, so references
// to both should point to the same copy relocation and that location should be
// what `get_w` returns.
extern int w1;
extern int s1;
int get_w1(void);
int get_s1(void);

// This time we only reference the non-weak symbol.
extern int s2;
int get_s2(void);
int get_w2(void);

// Lastly, we reference the weak symbol and not the strong one.
extern int w3;
int get_s3(void);
int get_w3(void);

// This is defined in a separate object file that is compiled with -fPIC.
int get_s1_pic(void);

void _start(void) {
  runtime_init();

  // Reference both the weak and the strong versions of the symbol.
  w1 = 10;
  if (get_w1() != 10) {
    exit_syscall(20);
  }
  if (get_s1() != 10) {
    exit_syscall(21);
  }
  if (get_s1_pic() != 10) {
    exit_syscall(22);
  }
  s1 = 11;
  if (get_w1() != 11) {
    exit_syscall(30);
  }
  if (get_s1() != 11) {
    exit_syscall(31);
  }
  if (get_s1_pic() != 11) {
    exit_syscall(32);
  }

  // Strong only. Note, we don't check get_w2 since linker behaviour differs in
  // this case. GNU ld doesn't export the weak alias, lld and Wild do.
  s2 = 12;
  if (get_s2() != 12) {
    exit_syscall(40);
  }

  // Weak only.
  w3 = 13;
  if (get_w3() != 13) {
    exit_syscall(50);
  }
  if (get_s3() != 13) {
    exit_syscall(51);
  }

  exit_syscall(42);
}
