ENTRY(_start)

text_start = SEGMENT_START("text", 0x600000);
rodata_start = SEGMENT_START("rodata", 0x600000);
data_start = SEGMENT_START("data", 0);
bss_start = SEGMENT_START("bss", 0);

SECTIONS {
  . = 0x600000;
  .text : {
    *(.text .text.*)
  }
  .rodata : { *(.rodata .rodata.*) }
  .data : { *(.data .data.*) }
  .bss : { *(.bss .bss.*) }
}
