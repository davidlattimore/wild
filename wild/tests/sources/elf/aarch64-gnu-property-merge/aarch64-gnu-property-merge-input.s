.text
ret
// Single .note.gnu.property section with TWO property entries in one note.
// This triggers the bug where Wild ANDs BTI(1) & PAC(2) = 0 instead of OR-ing.
.section ".note.gnu.property", "a"
.p2align 3
.long 4           // namesz
.long 0x20        // descsz = 32 bytes (two 16-byte property entries)
.long 5           // type NT_GNU_PROPERTY_TYPE_0
.asciz "GNU"
.p2align 3
// Property 1: BTI
.long 0xc0000000  // GNU_PROPERTY_AARCH64_FEATURE_1_AND
.long 4           // pr_datasz
.long 1           // BTI
.long 0           // padding
// Property 2: PAC
.long 0xc0000000  // GNU_PROPERTY_AARCH64_FEATURE_1_AND
.long 4           // pr_datasz
.long 2           // PAC
.long 0           // padding
