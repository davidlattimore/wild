//#AbstractConfig:default
//#Object:exit.c

//#Config:undefined:default
//#LinkArgs:--undefined=foo -u bar
//#ExpectSym:foo
//#ExpectSym:bar

// Verify that we can activate an archive entry by listing a symbol it defines as undefined.
//#Config:archive-activation:default
//#Archive:archive_activation0.c
//#CompArgs:-DEXPECT_ARCH0
//#LinkArgs:--undefined=bar

#include "exit.h"

__attribute__ ((weak)) int is_archive0_loaded() {
    return 0;
}

void _start(void) {
    #ifdef EXPECT_ARCH0
    if (!is_archive0_loaded()){
        exit_syscall(10);
    }
    #endif

    exit_syscall(42);
}
