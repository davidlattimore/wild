//#AbstractConfig:default
// clang + DWARF5 so the compiler emits `.debug_str_offsets` (gcc keeps string offsets inline);
// the bug is a relocation from `.debug_str_offsets` into a compressed `.debug_str`.
//#Compiler:clang
//#CompArgs:-g -gdwarf-5
//#Object:runtime.c
//#DiffIgnore:section.debug_*
// `debug_info`: at this scale wild and GNU ld compress `.debug_info` to different sizes; that
// cross-linker difference is unrelated to the merge-string bug under test.
//#DiffIgnore:debug_info
// wild types `.eh_frame` as SHT_PROGBITS where GNU ld uses SHT_X86_64_UNWIND; a pre-existing
// cosmetic difference, unrelated to this bug.
//#DiffIgnore:section.eh_frame.type
// Link-only: this reproduces a link-time failure (#2113), and a statically linked test binary
// can't be executed in every CI environment.
//#RunEnabled:false

//#Config:zlib:default
//#LinkArgs:--no-gc-sections --compress-debug-sections=zlib

#include "../common/runtime.h"

// Regression test for #2113. With `--compress-debug-sections`, a merge-string debug section
// (`.debug_str`) that actually compresses had its merged-strings map freed after compression,
// before `.debug_str_offsets` relocations into it were resolved, causing "Failed to find
// merge-string at offset 0". We need *enough* distinct, compressible debug strings that
// `.debug_str` compresses (and so is freed); a narrow program doesn't trigger it. Each instance
// contributes distinct type/member/function names to `.debug_str`.
#define GENERATE_DEBUG_STUFF(id)                          \
  struct data_blob_##id {                                 \
    int field_a_##id;                                     \
    char field_b_##id[32];                                \
    double field_c_##id;                                  \
    float field_d_##id;                                   \
  };                                                      \
  void function_for_id_##id(struct data_blob_##id* ptr) { \
    if (ptr) ptr->field_a_##id = id;                      \
  }

#define EXPAND_10(base)         \
  GENERATE_DEBUG_STUFF(base##0) \
  GENERATE_DEBUG_STUFF(base##1) \
  GENERATE_DEBUG_STUFF(base##2) \
  GENERATE_DEBUG_STUFF(base##3) \
  GENERATE_DEBUG_STUFF(base##4) \
  GENERATE_DEBUG_STUFF(base##5) \
  GENERATE_DEBUG_STUFF(base##6) \
  GENERATE_DEBUG_STUFF(base##7) \
  GENERATE_DEBUG_STUFF(base##8) \
  GENERATE_DEBUG_STUFF(base##9)

#define EXPAND_100(base) \
  EXPAND_10(base##0)     \
  EXPAND_10(base##1)     \
  EXPAND_10(base##2)     \
  EXPAND_10(base##3)     \
  EXPAND_10(base##4)     \
  EXPAND_10(base##5)     \
  EXPAND_10(base##6)     \
  EXPAND_10(base##7)     \
  EXPAND_10(base##8)     \
  EXPAND_10(base##9)

EXPAND_100(1)
EXPAND_100(2)
EXPAND_100(3)
EXPAND_100(4)
EXPAND_100(5)
EXPAND_100(6)
EXPAND_100(7)
EXPAND_100(8)
EXPAND_100(9)
EXPAND_100(10)
EXPAND_100(11)
EXPAND_100(12)
EXPAND_100(13)
EXPAND_100(14)
EXPAND_100(15)
EXPAND_100(16)
EXPAND_100(17)
EXPAND_100(18)
EXPAND_100(19)
EXPAND_100(20)
EXPAND_100(21)
EXPAND_100(22)
EXPAND_100(23)
EXPAND_100(24)
EXPAND_100(25)
EXPAND_100(26)
EXPAND_100(27)
EXPAND_100(28)
EXPAND_100(29)
EXPAND_100(30)

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
