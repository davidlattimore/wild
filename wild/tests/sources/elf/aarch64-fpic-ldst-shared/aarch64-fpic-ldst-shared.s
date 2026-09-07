// Verifies that Wild rejects LDST ABS_LO12 relocations in shared objects.
// These relocations encode absolute addresses and cannot be position-independent.
// Wild should error with "recompile with -fPIC" matching lld behavior.
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
    ldrb w0, [x0, :lo12:dat]   // R_AARCH64_LDST8_ABS_LO12_NC - rejected
    ldr w0, [x0, :lo12:dat]    // R_AARCH64_LDST32_ABS_LO12_NC - rejected
    ldr x0, [x0, :lo12:dat]    // R_AARCH64_LDST64_ABS_LO12_NC - rejected
