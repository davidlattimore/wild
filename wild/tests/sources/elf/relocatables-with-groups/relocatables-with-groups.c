//#EnableLinker:lld
//#Object:runtime.c
//#Relocatable:a.cc,b.cc

#include "../common/runtime.h"

int use_a();
int use_b();

void _start() { exit_syscall(use_a() + use_b()); }
