//#AbstractConfig:default
//#LinkerScript:linker-script-segment-start.ld
//#Object:runtime.c
//#Object:ptr_black_box.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default
// linker script)
//#SkipArch:riscv64
// ld merges all sections into a single segment when no PHDRS are specified,
// while wild uses separate RO/RX/RW segments.
//#DiffIgnore:segment.LOAD.RWX.alignment
//#DiffIgnore:segment.LOAD.RX.alignment
// Wild uses alignment 1 for .text when the linker script doesn't specify it;
// GNU ld uses the architecture's natural instruction alignment (4 on aarch64).
//#DiffIgnore:section.text.alignment

// Config 1: no -T flags — SEGMENT_START returns the linker script defaults.
// Defaults are 0x10/0x11/0x12/0x13 — distinct from actual section addresses
// to prove SEGMENT_START returns the default, not the actual segment address.
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
extern char local_text_start;
extern char expr;

void _start(void) {
  runtime_init();

  /* Variant 0: no -T flags, SEGMENT_START returns the linker script defaults
   * (0x10, 0x11, 0x12, 0x13). These are intentionally distinct from the actual
   * section addresses to prove SEGMENT_START returns the default, not the
   * segment address.
   * Variant 1: -T overrides. rodata has no -Trodata so it still returns 0x11.
   */
  int variant = VARIANT;

  unsigned long expect_text = (variant == 0) ? 0x10 : 0x700000;
  unsigned long expect_rodata = 0x11; /* no -Trodata, always default */
  unsigned long expect_data = (variant == 0) ? 0x12 : 0x800000;
  unsigned long expect_bss = (variant == 0) ? 0x13 : 0x900000;
  unsigned long expect_local_text = expect_text;
  unsigned long expect_expr = (expect_text << 2) + expect_rodata;

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

  if (ptr_to_int(&local_text_start) != expect_local_text) {
    exit_syscall(14);
  }

  if (ptr_to_int(&expr) != expect_expr) {
    exit_syscall(15);
  }

  exit_syscall(42);
}
