//#Mode:dynamic
//#RunEnabled:false
//#ReferenceLinkers:lld
//#LinkArgs:-shared -z now -T ./linker-script-fill.ld
//#DiffIgnore:section.got
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment
//#ExpectSectionBytes:.fill1=0x110000009000000022 0..9
//#ExpectSectionBytes:.fill2=0x110000009000000022 0..9
//#ExpectSectionBytes:.fill3=0x119090909090909022 0..9
//#ExpectSectionBytes:.fill4=0x110000009000000022 0..9
//#ExpectSectionBytes:.fill5=0x110000000900000022 0..9

__attribute__((section(".fill1.first"), aligned(8))) char fill1_first = 0x11;
__attribute__((section(".fill1.second"), aligned(8))) char fill1_second = 0x22;

__attribute__((section(".fill2.first"), aligned(8))) char fill2_first = 0x11;
__attribute__((section(".fill2.second"), aligned(8))) char fill2_second = 0x22;

__attribute__((section(".fill3.first"), aligned(8))) char fill3_first = 0x11;
__attribute__((section(".fill3.second"), aligned(8))) char fill3_second = 0x22;

__attribute__((section(".fill4.first"), aligned(8))) char fill4_first = 0x11;
__attribute__((section(".fill4.second"), aligned(8))) char fill4_second = 0x22;

__attribute__((section(".fill5.first"), aligned(8))) char fill5_first = 0x11;
__attribute__((section(".fill5.second"), aligned(8))) char fill5_second = 0x22;

int main() { return 0; }
