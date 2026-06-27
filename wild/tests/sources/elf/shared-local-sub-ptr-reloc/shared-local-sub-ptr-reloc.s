//#Arch:x86_64
//#Mode:dynamic
//#LinkArgs:-shared --no-gc-sections
//#ExpectError:R_X86_64_8
//#ExpectErrorWild:R_X86_64_8.*cannot be used when making a shared object

.data
local_byte:
  .byte 0
  .byte local_byte
  .short local_byte
