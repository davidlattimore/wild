// Test that R_X86_64_8 and R_X86_64_16 accept the full mixed range [-128, 255] and
// [-32768, 65535] respectively, not just the signed range.
//#Arch:x86_64
//#LinkArgs:-nostdlib --no-gc-sections
//#Mode:static
//#RunEnabled:false

.globl _start
_start:
    ret

.data
.byte foo8_max - 1
.byte foo8_mid - 1
.byte foo8_base - 129

.short foo16_max - 1
.short foo16_mid - 1
.short foo16_base - 32769

.globl foo8_max
foo8_max = 256

.globl foo8_mid
foo8_mid = 128

.globl foo8_base
foo8_base = 1

.globl foo16_max
foo16_max = 65536

.globl foo16_mid
foo16_mid = 32768

.globl foo16_base
foo16_base = 1
