//#Config:default
//#SkipArch: ppc64le
//#LinkArgs:--nmagic -z relro
//#Object:runtime.c
//#NoProgramHeader:PHDR
//#NoProgramHeader:INTERP
//#NoProgramHeader:GNU_RELRO
//#DoesNotContain:relro
// ld merges the first two LOAD segments with --nmagic, while wild and LLD do not
//#SkipLinker:ld
//#EnableLinker:lld
//#RunEnabled:false
//#ExpectLoadAlignment:0x8 0x20

//#Config:warn-max-page-size:default
//#SkipArch: ppc64le
//#LinkArgs:--nmagic -z max-page-size=65536
//#ExpectWarningWild:-z max-page-size is incompatible with --nmagic

//#Config:no-dynamic-linking:default
// Re-enable ppc64le here: this config links fine, but inherits the SkipArch from `default`.
//#Arch: x86_64,aarch64,riscv64,loongarch64,ppc64le
//#Shared:force-dynamic-linking.c
//#ExpectError:(?i)Attempted static link of dynamic object

#include "../common/runtime.h"

// Force the .text section to align to 32 bytes rather than the target architecture's instruction
// size to smooth out any differences when testing.
__attribute__((aligned(32))) void _start(void) {
  runtime_init();
  exit_syscall(42);
}
