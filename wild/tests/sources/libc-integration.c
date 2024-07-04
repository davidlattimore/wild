// This test links against libc and checks that various things work as expected.

//#AbstractConfig:default
//#DiffIgnore:.got.plt
//#DiffIgnore:.dynamic.DT_PLTGOT
//#DiffIgnore:.dynamic.DT_JMPREL
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_PLTREL
// TODO: Figure out these flags
//#DiffIgnore:.dynamic.DT_FLAGS
//#DiffIgnore:.dynamic.DT_FLAGS_1
//#DiffIgnore:section.plt.entsize
//#CompArgs:-g -ftls-model=global-dynamic
//#DoesNotContain:.debug_str

//#Config:clang-static:default
//#LinkArgs:--cc=clang -static -Wl,--strip-debug -Wl,--gc-sections
//#Object:libc-integration-0.c

//#Config:clang-static-pie:default
//#LinkArgs:--cc=clang -static-pie -Wl,--strip-debug -Wl,--gc-sections
//#Object:libc-integration-0.c

//#Config:gcc-static:default
//#LinkArgs:--cc=gcc -static -Wl,--strip-debug -Wl,--gc-sections
//#Object:libc-integration-0.c

//#Config:gcc-static-pie:default
//#LinkArgs:--cc=gcc -static-pie -Wl,--strip-debug -Wl,--gc-sections
//#Object:libc-integration-0.c

//#Config:clang-dynamic:default
//#CompArgs:-g -fPIC -ftls-model=initial-exec
//#LinkArgs:--cc=clang -fPIC -dynamic -Wl,--strip-debug -Wl,--gc-sections -Wl,-rpath,$ORIGIN
//#EnableLinker:lld
//#Shared:libc-integration-0.c
//#DiffIgnore:section.relro_padding

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

void set_tvar_local(int v);
int get_tvar_local(void);
void set_tvar_local2(int v);
int get_tvar_local2(void);
int get_weak_var(void);
int get_weak_var2(void);
int get_weak_tvar(void);
int get_weak_tvar2(void);
int compute_value10(void);

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

    if (weak_fn1) {
        return weak_fn1();
    }
    if (weak_fn2) {
        return weak_fn2();
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

    return 42;
}
