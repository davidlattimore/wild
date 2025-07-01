// Makes sure that having both verdef and verneed doesn't cause problems.

//#Mode:dynamic
//#Object:runtime.c
//#LinkArgs:-z now --version-script ./mixed-verdef-verneed.map
//#Shared:mixed-verdef-verneed-2.c
//#DiffIgnore:version_d.verdef_1
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:.dynamic.DT_RELA*
//#DiffIgnore:section.got

#include "runtime.h"

int from_so(void);

int bar_global(void) {
    return 10;
}

void _start(void) {
    runtime_init();

    if (bar_global() != 10) {
        exit_syscall(bar_global());
    }

    if (from_so() != 30) {
        exit_syscall(100);
    }

    exit_syscall(42);
}
