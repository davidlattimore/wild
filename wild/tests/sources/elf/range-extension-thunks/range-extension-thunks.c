// Note, this is a pretty expensive test, since we create several 64 MiB input
// files. The output file includes all of this, so is also large. For that
// reason, we try to do as much as we can in this one test. We avoid unnecessary
// configs and only enable for architectures where we support range-extension
// thunks.
//
// On aarch64, thunks may be needed in order to branch more than 128 MiB. LLD
// places the PLT after .text, while GNU ld and Wild places it before. For this
// reason, we put stuff in middle.c with 128 MiB of padding on either side. That
// way it doesn't matter which side the PLT is placed on, we'll need a thunk to
// branch to it.

//#LinkerDriver:gcc
//#Object:ifunc1.c
//#Object:padding1.c
//#Object:padding2.c
//#Object:middle1.c
//#Object:middle2.c
//#Object:padding3.c
//#Object:padding4.c
//#Object:get_3_aligned.c
//#Shared:shared.c
//#SoSingleLinker:lld
//#MaxThunks:20
//#Arch:aarch64
// We only test with lld, since GNU ld doesn't seem to be able to create thunks
// for ifuncs.
//#SkipLinker:ld
//#EnableLinker:lld
//#DiffIgnore:section.rodata
//#DiffIgnore:section.got.plt.entsize
//#DiffIgnore:section.iplt
//#DiffIgnore:section.gnu.version_r.alignment
// On Ubuntu 24.04, lld ends up setting the INFO flag for .rela.dyn.
//#DiffIgnore:section.rela.dyn.flags
//#DiffIgnore:section.data

int foo1(void);
int foo2(void);
int foo3(void);

int bar1(void);
int bar2(void);
int bar3(void);

int ifunc1(void);
int shared1(void);

int call_foo3_custom1(void);
int call_shared1_from_far1(void);
int call_shared1_from_far2(void);
int call_ifunc1_from_far1(void);
int call_ifunc2_from_far1(void);
int call_ifunc1_from_far2(void);
int call_ifunc2_from_far2(void);
int call_get_3(void);

__attribute__((section("foo_calls"))) int call_foo3_custom0(void) {
  return foo3();
}

int main() {
  if (foo1() != 1) {
    return 1;
  }
  if (foo2() != 2) {
    return 2;
  }
  if (foo3() != 3) {
    return 3;
  }
  if (bar1() != 11) {
    return 11;
  }
  if (bar2() != 12) {
    return 12;
  }
  if (bar3() != 13) {
    return 13;
  }
  if (call_foo3_custom0() != 3) {
    return 20;
  }
  if (call_foo3_custom1() != 3) {
    return 21;
  }
  if (shared1() != 42) {
    return 22;
  }
  if (call_shared1_from_far1() != 42) {
    return 23;
  }
  if (ifunc1() != 10) {
    return 24;
  }
  if (call_ifunc1_from_far1() != 10) {
    return 25;
  }
  if (call_ifunc2_from_far1() != 99) {
    return 26;
  }
  if (call_ifunc1_from_far2() != 10) {
    return 27;
  }
  if (call_ifunc2_from_far2() != 99) {
    return 28;
  }
  if (call_shared1_from_far2() != 42) {
    return 29;
  }
  if (call_get_3() != 3) {
    return 30;
  }
  return 42;
}
