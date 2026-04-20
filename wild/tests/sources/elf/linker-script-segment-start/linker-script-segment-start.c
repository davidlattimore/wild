//#LinkerScript:linker-script-segment-start.ld
//#Object:runtime.c
//#Object:ptr_black_box.c
// RISC-V: BFD complains about missing __global_pointer$ (defined in the default
// linker script)
//#SkipArch:riscv64
// ld merges all sections into a single RWE segment when no PHDRS are specified,
// while wild uses separate RO/RX/RW segments. Ignore the resulting layout
// diffs.
//#DiffIgnore:segment.LOAD.RWX.alignment
//#DiffIgnore:segment.LOAD.RX.alignment

#include <stddef.h>

#include "../common/runtime.h"
#include "ptr_black_box.h"

/* Symbols defined via SEGMENT_START for each supported segment type */
extern char text_start;
extern char rodata_start;
extern char data_start;
extern char bss_start;

/* Variables in each segment to verify the segment start is <= them */
static const int rodata_var = 42;
static int data_var = 1;
static int bss_var;

void _start(void) {
  runtime_init();

  /* text_start must be <= _start (both in the text segment) */
  if (ptr_to_int(&text_start) > ptr_to_int(&_start)) {
    exit_syscall(10);
  }

  /* rodata_start must be <= rodata_var */
  if (ptr_to_int(&rodata_start) > ptr_to_int(&rodata_var)) {
    exit_syscall(11);
  }

  /* data_start must be <= data_var */
  if (ptr_to_int(&data_start) > ptr_to_int(&data_var)) {
    exit_syscall(12);
  }

  /* bss_start must be <= bss_var */
  if (ptr_to_int(&bss_start) > ptr_to_int(&bss_var)) {
    exit_syscall(13);
  }

  exit_syscall(42);
}
