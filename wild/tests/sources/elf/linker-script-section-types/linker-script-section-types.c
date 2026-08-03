//#Config:default
//#RunEnabled:false
//#LinkArgs:-shared
//#ReferenceLinkers:bfd
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#DiffIgnore:section.got
//#LinkerScript:linker-script-section-types.ld
//#ExpectSection:.section.readonly flags=A
//#ExpectSection:.section.noload flags=WA,type=0x8
//#ExpectSection:.section.dsect flags=W
//#ExpectSection:.section.copy flags=W
//#ExpectSection:.section.info flags=W
//#ExpectSection:.section.overlay flags=W

__attribute__((section(".section.noload"))) char noload = 0;
__attribute__((section(".section.readonly"))) char readonly = 0;
__attribute__((section(".section.dsect"))) char dsect = 0;
__attribute__((section(".section.copy"))) char copy = 0;
__attribute__((section(".section.info"))) char info = 0;
__attribute__((section(".section.overlay"))) char overlay = 0;
