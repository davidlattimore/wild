//#Arch: x86_64
//#ReferenceLinkers:bfd,lld
//#RequiresCompilerFlags:-gz=zlib
//#Object:runtime.c
//#Relocatable:partial-link-compressed-singleton-input.c:-g -gz=zlib

#include "../common/runtime.h"

int compressed_singleton_value(void);

void _start(void) {
  runtime_init();
  exit_syscall(compressed_singleton_value());
}
