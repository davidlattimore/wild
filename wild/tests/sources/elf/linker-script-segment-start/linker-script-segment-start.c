//#AbstractConfig:default
//#LinkerScript:linker-script-segment-start.ld
//#Object:runtime.c
//#Object:ptr_black_box.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default
// linker script)
//#SkipArch:riscv64

// Config 1: no -T flags — SEGMENT_START returns the linker script defaults.
// text/rodata default to 0x600000, data/bss default to 0.
//#Config:no-overrides:default
//#Variant:0

// Config 2: -Ttext/-Tdata/-Tbss overrides. Both Wild and GNU ld honor these
// alongside a linker script. lld ignores -T* when a linker script is present,
// so we skip it here.
//#Config:with-T-overrides:default
//#SkipLinker:lld
//#LinkArgs:-Ttext=0x700000 -Tdata=0x800000 -Tbss=0x900000
//#Variant:1

#include "../common/ptr_black_box.h"
#include "../common/runtime.h"

extern char text_start;
extern char rodata_start;
extern char data_start;
extern char bss_start;

void _start(void) {
  runtime_init();

  /* Variant 0: no -T flags, SEGMENT_START returns the linker script defaults.
   * Variant 1: -T overrides passed to Wild. rodata has no -T flag so it
   *            still returns its default 0x600000. */
  int variant = VARIANT;

  unsigned long expect_text = (variant == 0) ? 0x600000 : 0x700000;
  unsigned long expect_rodata = 0x600000; /* no -Trodata, always default */
  unsigned long expect_data = (variant == 0) ? 0 : 0x800000;
  unsigned long expect_bss = (variant == 0) ? 0 : 0x900000;

  if (ptr_to_int(&text_start) != expect_text) {
    exit_syscall(10);
  }

  if (ptr_to_int(&rodata_start) != expect_rodata) {
    exit_syscall(11);
  }

  if (ptr_to_int(&data_start) != expect_data) {
    exit_syscall(12);
  }

  if (ptr_to_int(&bss_start) != expect_bss) {
    exit_syscall(13);
  }

  exit_syscall(42);
}
