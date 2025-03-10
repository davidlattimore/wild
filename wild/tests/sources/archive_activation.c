//#AbstractConfig:default
//#CompArgs:-ffunction-sections
//#EnableLinker:lld

//#Config:regular:default
//#Archive:archive_activation0.c
//#Archive:archive_activation1.c
//#Archive:exit.c
//#Archive:empty.a

//#Config:thin:default
//#ThinArchive:archive_activation0.c
//#ThinArchive:archive_activation1.c
//#ThinArchive:exit.c
//#ThinArchive:empty.a

//#Config:lib:default
// GNU ld doesn't yet support --start-lib
//#SkipLinker:ld
//#Cross:false
//#LinkArgs:--start-lib
//#Object:archive_activation0.c
//#Object:archive_activation1.c
//#Object:exit.c
//#Object:empty.a

#include "exit.h"

int bar(void);
int does_not_exist(void);

__attribute__ ((weak)) int is_archive0_loaded() {
    return 0;
}

__attribute__ ((weak)) int is_archive1_loaded() {
    return 0;
}

void _start(void) {
    if (!is_archive0_loaded()) {
        exit_syscall(101);
    }
    if (is_archive1_loaded()) {
        exit_syscall(102);
    }
    exit_syscall(42);
}

// The following function is dead code. It's not referenced from anywhere and will be GCed when we
// link. However its presence, or rather the reference that it contains to the function `bar` causes
// the archive member containing `bar` to be activated, which causes an alternate version of
// `is_archive_loaded` to be used, one which returns 1 rather than 0.
void load_bar(void) {
    bar();

    // While we're here, make sure that we can reference a function that isn't defined anywhere and
    // not fail to link, since this code gets GCed.
    does_not_exist();
}
