// Verifies that we can correctly handle an IFUNC and TLSGD without startup files. The lack of
// startup files is important, because the startup files can add additional GOT entries which can
// mask bugs in this area.

//#AbstractConfig:default
//#Object:runtime.c
//#CompArgs:-fPIC -ftls-model=global-dynamic
//#LinkerDriver:gcc
//#LinkArgs:-nostartfiles -Wl,-z,now -Wl,--no-as-needed
//#RequiresGlibc:true
//#ReferenceLinkers:bfd,lld
//#DiffMatchAny:true
//#DiffIgnore:section.rodata
//#DiffIgnore:.dynamic.DT_VERNEED
//#DiffIgnore:.dynamic.DT_VERSYM
//#DiffIgnore:section.gnu.version
//#DiffIgnore:section.gnu.version_r

//#Config:riscv:default
//#Arch:riscv64
// LLD seems to do something wrong here.
//#ReferenceLinkers:bfd

//#Config:other:default
//#SkipArch:ppc64le,riscv64

#include "../common/runtime.h"

static __thread volatile int tls_value = 40;

static int implementation(void) { return tls_value + 2; }

static void* resolve_function(void) { return implementation; }

int indirect_function(void) __attribute__((ifunc("resolve_function")));

void _start(void) {
  runtime_init();
  exit_syscall(indirect_function());
}
