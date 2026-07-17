// Verify that --sort-section=name sorts input sections alphabetically.
// Also verifies that exported symbols in sorted sections work correctly.
// Without sorting: .data.zzz (0x33) comes first (input order)
// With --sort-section=name: .data.aaa (0x11) comes first (alphabetical)
//#AbstractConfig:default
//#LinkArgs:-shared --no-gc-sections --sort-section=name
//#RunEnabled:false
//#ReferenceLinkers:bfd
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#DiffIgnore:segment.LOAD.RX.alignment
//#Config:x86_64:default
//#Arch:x86_64
//#ExpectSectionBytes:.data=0x11000000000000003300000000000000 0..16
    .section .data.zzz,"aw",@progbits
    .balign 8
    .byte 0x33
    .zero 7

    .globl exported
    .section .data.aaa,"aw",@progbits
    .balign 8
exported:
    .byte 0x11
    .zero 7
