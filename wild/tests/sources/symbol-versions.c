//#Config:verneed
//#Object:exit.c
//#Object:symbol-versions-2.c
//#ExpectSym: _start .text
//#ExpectSym: exit_syscall .text
//#EnableLinker:lld

//#Config:verdef
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_FLAGS*
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:file-header.entry
//#DiffIgnore:rel.*
//#Object:exit.c
//#EnableLinker:lld
//#LinkArgs:--shared
//#VersionScript:symbol-versions-script

#include "exit.h"

int foo(void);

void _start(void) {
    if (foo() != 2) {
        exit_syscall(foo());
    }

    exit_syscall(42);
}

void bar_global(void) {
    exit_syscall(42);
}

// TODO: doesn't work, is global
void bar_local(void) {
    exit_syscall(42);
}

void bar_v2(void) {
    exit_syscall(42);
}
