// This verifies that the linker ORs GNU property entries within a single note
// (producing BTI|PAC = 0x3) rather than ANDing them (which would produce
// BTI&PAC = 0x0 and incorrectly discard the .note.gnu.property section).
// We use lld as reference linker because GNU ld cross linker does not output
// .note.gnu.property in static mode.
//#Arch:aarch64
//#Mode:static
//#ReferenceLinkers:lld
//#LinkArgs:--no-gc-sections
//#RunEnabled:false
//#ExpectSection:.note.gnu.property

.globl _start
_start:
    ret

.section ".note.gnu.property", "a"
.p2align 3
.long 4           // namesz
.long 0x20        // descsz = 32 bytes (two 16-byte property entries)
.long 5           // type NT_GNU_PROPERTY_TYPE_0
.asciz "GNU"
.p2align 3
.long 0xc0000000  // GNU_PROPERTY_AARCH64_FEATURE_1_AND
.long 4           // pr_datasz
.long 1           // BTI
.long 0           // padding
.long 0xc0000000  // GNU_PROPERTY_AARCH64_FEATURE_1_AND
.long 4           // pr_datasz
.long 2           // PAC
.long 0           // padding
