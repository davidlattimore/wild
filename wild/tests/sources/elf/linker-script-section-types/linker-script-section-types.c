//#Config:default
//#RunEnabled:false
//#LinkArgs:-shared
//#ReferenceLinkers:bfd
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#DiffIgnore:section.got
//#DiffIgnore:segment.LOAD.RWX.alignment
//#DiffIgnore:segment.LOAD.RX.alignment
//#LinkerScript:linker-script-section-types.ld
//#ExpectSection:.section.readonly.wa flags=A
//#ExpectSection:.section.noload.wa flags=WA,type=0x8
//#ExpectSection:.section.dsect.wa flags=W
//#ExpectSection:.section.copy.wa flags=W
//#ExpectSection:.section.info.wa flags=W
//#ExpectSection:.section.overlay.wa flags=W
//#ExpectSection:.section.readonly.ax flags=AX
//#ExpectSection:.section.noload.ax flags=AX,type=0x8
//#ExpectSection:.section.dsect.ax flags=X
//#ExpectSection:.section.readonly.a flags=A
//#ExpectSection:.section.noload.a flags=A,type=0x8
//#ExpectSection:.section.dsect.a flags=''

__attribute__((section(".section.noload.wa"))) char noload_wa = 0;
__attribute__((section(".section.readonly.wa"))) char readonly_wa = 0;
__attribute__((section(".section.dsect.wa"))) char dsect_wa = 0;
__attribute__((section(".section.copy.wa"))) char copy_wa = 0;
__attribute__((section(".section.info.wa"))) char info_wa = 0;
__attribute__((section(".section.overlay.wa"))) char overlay_wa = 0;

__attribute__((section(".section.readonly.ax"))) char readonly_ax() { return 0; }
__attribute__((section(".section.noload.ax"))) char noload_ax() { return 0; }
__attribute__((section(".section.dsect.ax"))) char dsect_ax() { return 0; }

const __attribute__((section(".section.noload.a"))) char noload_a = 0;
const __attribute__((section(".section.readonly.a"))) char readonly_a = 0;
const __attribute__((section(".section.dsect.a"))) char dsect_a = 0;
