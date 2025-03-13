//#AbstractConfig:verdef
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_FLAGS*
//#DiffIgnore:.dynamic.DT_RELA
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:file-header.entry
//#Object:exit.c
//#EnableLinker:lld
//#VersionScript:symbol-versions-script.map

//#Config:verneed
//#Object:exit.c
//#Object:symbol-versions-2.c
//#ExpectSym: _start .text
//#ExpectSym: exit_syscall .text
//#EnableLinker:lld

//#Config:verdef-0:verdef
//#DiffIgnore:version_d.verdef_1
//#LinkArgs:--shared

//#Config:verdef-1:verdef
//#LinkArgs:--shared --soname=symbol-versions.so

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

void bar_v2_1(void) {
    exit_syscall(42);
}
