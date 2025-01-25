// This test links against libc and checks that various things work as expected.

//#AbstractConfig:default
//#DiffIgnore:.got.plt
//#DiffIgnore:.dynamic.DT_PLTGOT
//#DiffIgnore:.dynamic.DT_JMPREL
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_PLTREL
//#DiffIgnore:section.plt.entsize
//#DiffIgnore:section.rodata.cst32.entsize
// This is only an issue on openSUSE
//#DiffIgnore:section.rela.plt.link
//#CompArgs:-g -ftls-model=global-dynamic
//#RequiresGlibc:true

//#Config:clang-static:default
//#LinkArgs:--cc=clang -static -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c

//#Config:clang-static-pie:default
//#CompArgs:-fPIE -fPIC
//#LinkArgs:--cc=clang -static-pie -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c

//#Config:gcc-static:default
//#LinkArgs:--cc=gcc -static -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c

//#Config:gcc-static-pie:default
//#CompArgs:-fPIE -DVERIFY_CTORS
//#LinkArgs:--cc=gcc -static-pie -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Object:libc-integration-0.c
//#Object:libc-integration-1.c

//#Config:clang-initial-exec:default
//#CompArgs:-g -fPIC -ftls-model=initial-exec -DDYNAMIC_DEP
//#LinkArgs:--cc=clang -fPIC -dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-rpath,$ORIGIN -Wl,-z,now
//#EnableLinker:lld
//#Shared:libc-integration-0.c
//#Shared:libc-integration-1.c
//#DiffIgnore:section.relro_padding

//#Config:clang-global-dynamic:default
//#Compiler:clang
//#CompArgs:-g -fPIC -ftls-model=global-dynamic -DDYNAMIC_DEP
//#LinkArgs:--cc=clang -fPIC -dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-rpath,$ORIGIN -Wl,-z,now
//#EnableLinker:lld
//#Shared:libc-integration-0.c
//#Shared:libc-integration-1.c
//#DiffIgnore:section.relro_padding
//#DiffIgnore:section.rodata.entsize
//#DiffIgnore:section.rodata.flags

//#Config:gcc-dynamic-pie:default
//#CompArgs:-g -fpie -DDYNAMIC_DEP -DVERIFY_CTORS
//#CompSoArgs:-g -fPIC -ftls-model=global-dynamic
//#LinkArgs:--cc=gcc -dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Shared:libc-integration-0.c
//#Shared:libc-integration-1.c

//#Config:gcc-dynamic-no-pie:default
//#CompArgs:-g -no-pie -DDYNAMIC_DEP -DVERIFY_CTORS
//#CompSoArgs:-g -fPIC -ftls-model=global-dynamic
//#LinkArgs:--cc=gcc -dynamic -no-pie -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Shared:libc-integration-0.c
//#Shared:libc-integration-1.c

//#Config:gcc-dynamic-pie-large:default
//#CompArgs:-g -fpie -DDYNAMIC_DEP -mcmodel=large
//#CompSoArgs:-g -fPIC -ftls-model=global-dynamic
//#LinkArgs:--cc=gcc -dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-z,now
//#Shared:libc-integration-0.c
//#Shared:libc-integration-1.c

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

__thread int tvar1 = 0;
__thread int tvar2 = 70;
extern __thread int tvar3;

// These are defined both here and in the second file, but with different values.
__attribute__ ((weak)) int weak_var = 30;
__attribute__ ((weak)) __thread int weak_tvar = 31;

void set_tvar2(int v);

int __attribute__ ((weak)) weak_fn1(void);
int __attribute__ ((weak)) weak_fn2(void);

int __attribute__ ((weak)) sometimes_weak_fn(void) {
    return 7;
}

extern int value42;

const char* str1 = "This is str1";

static int ctors_init_val = 0;

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

typedef int(*get_int_fn_t)(void);

get_int_fn_t fn_pointers[] = {
    get_tvar_local,
    get_tvar_local2,
    get_weak_var,
    get_weak_var2,
    weak_fn1,
};

// Initialisation with .ctors currently seems to fail with lld (tested with 18.1.8). For that
// reason, we only enable this part of the test for selected variants that don't enable lld.
#ifdef VERIFY_CTORS

void init1() {
    ctors_init_val += 10;
}
__attribute__ ((section (".ctors"), used)) static void* init1_ptr = init1;

void init2() {
    ctors_init_val += 30;
}
__attribute__ ((section (".ctors"), used)) static void* init2_ptr = init2;

void init3() {
    ctors_init_val += 2;
}
__attribute__ ((section (".ctors"), used)) static void* init3_ptr = init3;

#endif

void *thread_function(void *data) {
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
    int ret = pthread_create(&thread1, NULL, thread_function, (void*) &thread1_out);

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

    // If our dependency is a shared object, then its strong definition won't override ours. However
    // if we're statically linking our dependency then its strong definition will override ours.
#ifdef DYNAMIC_DEP
    int expected = 7;
#else
    int expected = 42;
#endif
    if (sometimes_weak_fn() != expected) {
        return 116;
    }

    if (fn_pointers[2]() != 30) {
        return 118;
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
#ifdef VERIFY_CTORS
    if (ctors_init_val != 42) {
        return ctors_init_val;
    }
#endif

    return 42;
}
