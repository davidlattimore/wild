// Test that non-PIC AArch64 relocations error in shared objects.
// Wild errors with "recompile with -fPIC" matching lld behavior.
// GNU ld cross linker silently succeeds so we skip it.
//#Arch:aarch64
//#Mode:dynamic
//#ReferenceLinkers:lld
//#LinkArgs:-shared --no-gc-sections
//#ExpectError:recompile with -fPIC
//#RunEnabled:false

.globl dat
dat:
    .word 0

.text
.globl _start
_start:
    add x0, x0, :lo12:dat
