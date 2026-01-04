// This test links against libc and checks that various things work as expected.

//#AbstractConfig:default
//#DiffIgnore:.got.plt
//#DiffIgnore:.dynamic.DT_PLTGOT
//#DiffIgnore:.dynamic.DT_JMPREL
//#DiffIgnore:.dynamic.DT_PLTREL
// This is only an issue on openSUSE
//#DiffIgnore:section.rela.plt.link
//#DiffIgnore:section.data.alignment
//#DiffIgnore:section.rela.dyn
//#CompArgs:-g -ftls-model=global-dynamic
//#RequiresGlibc:true
// TODO: There are multiple variants of the test-case that fail with the BFD
// linker on RISC-V arch.
//#SkipArch: riscv64

//#AbstractConfig:shared:default
//#Shared:libc-integration-0.c,libc-integration-0b.c
//#Shared:libc-integration-1.c
//#TestUpdateInPlace:true
// Each binary links against shared objects created by that linker. So different
// names are expected.
//#DiffIgnore:.dynamic.DT_NEEDED

//#Config:clang-static:default
//#LinkerDriver:clang
//#LinkArgs:-static -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c
//#EnableLinker:lld
//#Cross: false

//#Config:clang-static-pie:default
//#CompArgs:-fPIE -fPIC
//#LinkerDriver:clang
//#LinkArgs:-static-pie -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#TestUpdateInPlace:true
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c
//#EnableLinker:lld
//#Cross: false

//#Config:gcc-static:default
//#LinkerDriver:gcc
//#LinkArgs:-static -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c
//#EnableLinker:lld

//#Config:gcc-static-pie:default
//#CompArgs:-fPIE
//#LinkerDriver:gcc
//#LinkArgs:-static-pie -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c
//#EnableLinker:lld
// Both ld and lld complain about a duplicate eh_frame info (loongarch64).
//#SkipArch: loongarch64,riscv64

//#Config:clang-initial-exec:shared
//#CompArgs:-g -fPIC -ftls-model=initial-exec -DDYNAMIC_DEP
//#LinkerDriver:clang
//#LinkArgs:-fPIC -dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-rpath,$ORIGIN -Wl,-z,now
//#EnableLinker:lld
//#Cross: false
//#DiffIgnore:section.relro_padding

//#Config:clang-global-dynamic:shared
//#Compiler:clang
//#CompArgs:-g -fPIC -ftls-model=global-dynamic -DDYNAMIC_DEP
//#LinkerDriver:clang
//#LinkArgs:-fPIC -dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-rpath,$ORIGIN -Wl,-z,now
//#EnableLinker:lld
//#Cross: false
//#DiffIgnore:section.relro_padding

// In addition to testing gcc-dynamic-pie, this also checks -L with a path that
// does not exist. It's necessary to test this on a test with a linker driver,
// so that we test that the savedir mechanism works with a non-existent path.
// Linker-driver tests are more expensive, so we double-up with testing other
// stuff.
//#Config:gcc-dynamic-pie:shared
//#CompArgs:-g -fpie -DDYNAMIC_DEP -DVERIFY_CTORS
//#CompSoArgs:-g -fPIC -ftls-model=global-dynamic
//#LinkerDriver:gcc
//#LinkArgs:-dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now -L./does/not/exist

//#Config:gcc-dynamic-no-pie:shared
//#CompArgs:-g -no-pie -DDYNAMIC_DEP -DVERIFY_CTORS
//#CompSoArgs:-g -fPIC -ftls-model=global-dynamic
//#LinkerDriver:gcc
// On nixos, with this configuration, GNU ld seems to only optimise TLSGD to
// initial-exec rather than local exec. lld does however still optimise to local
// exec, so we enable it as an additional reference point.
//#EnableLinker:lld
//#LinkArgs:-dynamic -no-pie -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now -L/does/not/exist

//#Config:gcc-dynamic-pie-large:shared
//#CompArgs:-g -fpie -DDYNAMIC_DEP -mcmodel=large
//#CompSoArgs:-g -fPIC -ftls-model=global-dynamic
//#LinkerDriver:gcc
//#LinkArgs:-dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
// TODO: cc1plus: sorry, unimplemented: code model 'large' with '-fPIC'
//#Arch: x86_64

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

__thread int tvar1 = 0;
__thread int tvar2 = 70;
extern __thread int tvar3;

// These are defined both here and in the second file, but with different
// values.
__attribute__((weak)) int weak_var = 30;
__attribute__((weak)) __thread int weak_tvar = 31;

void set_tvar2(int v);

int __attribute__((weak)) weak_fn1(void);
int __attribute__((weak)) weak_fn2(void);
int __attribute__((weak)) weak_fn3(void);

int __attribute__((weak)) sometimes_weak_fn(void) { return 7; }

extern int value42;

const char* str1 = "This is str1";

void set_tvar_local(int v);
int get_tvar_local(void);
void set_tvar_local2(int v);
int get_tvar_local2(void);
int get_weak_var(void);
int get_weak_var2(void);
int get_weak_tvar(void);
int get_weak_tvar2(void);
int compute_value10(void);
int black_box(int v);
int get_42(void);

typedef int (*get_int_fn_t)(void);

get_int_fn_t fn_pointers[] = {
    get_tvar_local, get_tvar_local2, get_weak_var, get_weak_var2, weak_fn1,
};

get_int_fn_t get_sometimes_weak_fn_ptr(void);

// Make sure that we can refer to a non-default version of a symbol from libc.
#if defined(__x86_64__)
__asm__(".symver old_timer_gettime, timer_gettime@GLIBC_2.2.5");
#elif defined(__aarch64__)
__asm__(".symver old_timer_gettime, timer_gettime@GLIBC_2.17");
#endif

// The signature here doesn't actually matter since we don't call it. Symbol is
// weak to prevent the compiler from assuming that it can never be null.
int __attribute__((weak)) old_timer_gettime();

void* thread_function(void* data) {
  if (tvar1 != 0) {
    return NULL;
  }
  if (tvar2 != 70) {
    return NULL;
  }

  int* data2 = (int*)malloc(100);
  memset(data2, 0, 100);

  tvar1 = 10;

  int* out = (int*)data;
  *out = 30;

  return NULL;
}

int main() {
  pthread_t thread1;
  int thread1_out;
  if (tvar1 != 0) {
    return 101;
  }
  if (tvar2 != 70) {
    return 102;
  }
  tvar1 = 20;
  int ret =
      pthread_create(&thread1, NULL, thread_function, (void*)&thread1_out);

  int* data = (int*)malloc(100);
  memset(data, 0, 100);

  pthread_join(thread1, NULL);

  if (tvar1 != 20) {
    return 103;
  }
  if (thread1_out != 30) {
    return 104;
  }
  if (tvar3 != 80) {
    return 105;
  }

  set_tvar2(77);
  if (tvar2 != 77) {
    return 106;
  }

  if (get_tvar_local() != 8) {
    return 107;
  }
  set_tvar_local(99);
  if (get_tvar_local() != 99) {
    return 108;
  }

  if (get_weak_var() != 30) {
    return 109;
  }

  if (get_weak_tvar() != 31) {
    return 110;
  }

  if (get_weak_var2() != 80) {
    return 111;
  }

  if (get_weak_tvar2() != 81) {
    return 112;
  }

  if (get_tvar_local2() != 70) {
    return 113;
  }
  set_tvar_local(25);
  if (get_tvar_local() != 25) {
    return 114;
  }

  if (compute_value10() != 10) {
    return 115;
  }

  // If our dependency is a shared object, then its strong definition won't
  // override ours. However if we're statically linking our dependency then its
  // strong definition will override ours.
#ifdef DYNAMIC_DEP
  int expected = 7;
#else
  int expected = 42;
#endif
  if (sometimes_weak_fn() != expected) {
    return 70;
  }

  if (get_sometimes_weak_fn_ptr()() != expected) {
    return 71;
  }

  if (fn_pointers[2]() != 30) {
    return 116;
  }

  if (value42 != 42) {
    return 117;
  }

  if (weak_fn1) {
    return 118;
  }
  if (weak_fn2) {
    return 119;
  }
  if (fn_pointers[black_box(4)]) {
    return 120;
  }
  if (get_42() != 42) {
    return 121;
  }
  if (strcmp(str1, "This is str1") != 0) {
    return 122;
  }

  if (weak_fn3() != 15) {
    return 124;
  }

#ifdef DYNAMIC_DEP
  if (&old_timer_gettime == NULL) {
    return 125;
  }
#endif

  // We have a weak, hidden definition of atoi in libc-integration-0.c. Provided
  // we're dynamically linking, that definition shouldn't be exported from the
  // shared object on account if it being hidden. That means that we should get
  // the proper definition from libc.
#ifdef DYNAMIC_DEP
  if (atoi("1000") != 1000) {
    return 126;
  }
#endif

  return 42;
}
