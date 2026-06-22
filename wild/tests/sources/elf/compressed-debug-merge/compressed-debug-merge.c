//#AbstractConfig:default
// clang + DWARF5 emits `.debug_str_offsets`; gcc keeps the string offsets inline.
//#Compiler:clang
//#CompArgs:-g -gdwarf-5
//#Object:runtime.c
//#DiffIgnore:section.debug_*
//#DiffIgnore:section.eh_frame.type

//#Config:zlib:default
//#LinkArgs:--compress-debug-sections=zlib

//#Config:zstd:default
//#RequiresLinkerFlags:--compress-debug-sections=zstd
//#LinkArgs:--compress-debug-sections=zstd

//#Config:none:default
//#LinkArgs:--compress-debug-sections=none

#include "../common/runtime.h"

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
