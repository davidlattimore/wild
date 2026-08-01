.text
ret
.section ".note.gnu.property", "a"
.p2align 3
.long 4           // namesz
.long 0x10        // descsz
.long 5           // type NT_GNU_PROPERTY_TYPE_0
.asciz "GNU"
.p2align 3
.long 0xc0000000  // GNU_PROPERTY_AARCH64_FEATURE_1_AND
.long 4           // pr_datasz
.long 1           // BTI
.p2align 3
.long 4           // namesz
.long 0x10        // descsz
.long 5           // type NT_GNU_PROPERTY_TYPE_0
.asciz "GNU"
.p2align 3
.long 0xc0000000  // GNU_PROPERTY_AARCH64_FEATURE_1_AND
.long 4           // pr_datasz
.long 2           // PAC
.p2align 3
