// This test links against libc and checks that various things work as expected.

//#CompArgs:debug:-g
//#LinkArgs:clang-static:--cc=clang -static -Wl,--strip-debug
//#LinkArgs:clang-static-pie:--cc=clang -static-pie -Wl,--strip-debug
//#LinkArgs:gcc-static:--cc=gcc -static -Wl,--strip-debug
//#LinkArgs:gcc-static-pie:--cc=gcc -static-pie -Wl,--strip-debug
//#LinkArgs:gcc-dynamic:--cc=gcc -dynamic -Wl,--strip-debug

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

__thread int tvar1 = 0;
__thread int tvar2 = 70;

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

    return 42;
}

//#DoesNotContain:.debug_str
