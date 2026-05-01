//#AbstractConfig:default
//#CompArgs:-g
//#Object:runtime.c
//#DiffIgnore:section.debug_*
//#ExpectSym:_start line=54

//#Config:zlib:default
//#LinkArgs:--compress-debug-sections=zlib

//#Config:zstd:default
//#RequiresLinkerFlags:--compress-debug-sections=zstd
//#LinkArgs:--compress-debug-sections=zstd

//#Config:none:default
//#LinkArgs:--compress-debug-sections=none

#include "../common/runtime.h"

// We need to have enough debug info that's sufficiently compressible for
// certain kinds of bugs to show up.
#define GENERATE_DEBUG_STUFF(id)                          \
  struct data_blob_##id {                                 \
    int field_a;                                          \
    char field_b[32];                                     \
    double field_c;                                       \
    float field_d;                                        \
  };                                                      \
  void function_for_id_##id(struct data_blob_##id* ptr) { \
    if (ptr) ptr->field_a = id;                           \
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

EXPAND_10(1)
EXPAND_10(2)
EXPAND_10(3)
EXPAND_10(4)
EXPAND_10(5)
EXPAND_10(6)
EXPAND_10(7)
EXPAND_10(8)
EXPAND_10(9)

void _start(void) {
  runtime_init();
  exit_syscall(42);
}
