// Verify that --sort-section=alignment sorts sections by alignment (largest first).
// Input order: .data.aaa (align 8) first, .data.zzz (align 64) second
// With --sort-section=alignment: .data.zzz (align 64) should come first
//#AbstractConfig:default
//#LinkArgs:-shared --no-gc-sections --sort-section=alignment
//#RunEnabled:false
//#ReferenceLinkers:bfd
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#DiffIgnore:segment.LOAD.RX.alignment
//#Config:x86_64:default
//#Arch:x86_64
//#ExpectSectionBytes:.data=0x3300000000000000 0..8

    .section .data.aaa,"aw",@progbits
    .balign 8
    .byte 0x11
    .zero 7

    .section .data.zzz,"aw",@progbits
    .balign 64
    .byte 0x33
    .zero 63
