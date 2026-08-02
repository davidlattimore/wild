//#LinkArgs: -T tests/sources/elf/script-sort/script-sort.ld
//#Object:runtime.c
//#Object:ptr_black_box.c
//#Object:script-sort-2.c
//#Object:script-sort-3.c
//#EnableLinker:lld
//#DiffMatchAny:true
//#ExpectSym:func_kept
//#NoSym:func_drop

#include "../common/ptr_black_box.h"
#include "../common/runtime.h"

extern int func_a();
extern int func_b();
extern int func_c();

extern int align_16();
extern int align_64();
extern int align_4();
extern int align_32();

void _start(void) {
  runtime_init();

  size_t a_addr = ptr_to_int(&func_a);
  size_t b_addr = ptr_to_int(&func_b);
  size_t c_addr = ptr_to_int(&func_c);

  if (a_addr >= b_addr) {
    exit_syscall(101);
  }
  if (b_addr >= c_addr) {
    exit_syscall(102);
  }

  if (func_a() != 1 || func_b() != 2 || func_c() != 3) {
    exit_syscall(103);
  }

  size_t align_16_addr = ptr_to_int(&align_16);
  size_t align_64_addr = ptr_to_int(&align_64);
  size_t align_4_addr = ptr_to_int(&align_4);
  size_t align_32_addr = ptr_to_int(&align_32);

  if (align_64_addr >= align_32_addr || align_32_addr >= align_16_addr ||
      align_16_addr >= align_4_addr) {
    exit_syscall(104);
  }

  exit_syscall(42);
}
