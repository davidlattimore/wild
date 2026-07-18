//#AbstractConfig:default
//#Mode:dynamic
//#RunEnabled:false
//#ReferenceLinkers:lld
//#LinkArgs:-shared -z now
//#DiffIgnore:section.got
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment

//#Config:fillexpr:default
//#LinkerScript:linker-script-fill.ld
//#ExpectSectionBytes:.fill1=0x110000009000000022 0..9
//#ExpectSectionBytes:.fill2=0x110000009000000022 0..9
//#ExpectSectionBytes:.fill3=0x119090909090909022 0..9
//#ExpectSectionBytes:.fill4=0x110000009000000022 0..9
//#ExpectSectionBytes:.fill5=0x110000000900000022 0..9
//#ExpectSectionBytes:.fill6=0x90909090909090901190909090909090 0..16
//#ExpectSectionBytes:.fill6=0x90909090909090902290909090909090 16..32

//#Config:overflow-u32:default
//#LinkerScript:linker-script-fill-overflow.ld
//#ExpectError:.*(?i-u)filler expression result does not fit 32-bit: 0x9090909090

//#Config:negative-fill:default
//#LinkerScript:linker-script-fill-neg.ld
//#ExpectError:.*(?i-u)filler expression result does not fit 32-bit: 0xffffffffffffffff

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

__attribute__((section(".fill6.first"), aligned(8))) char fill7_first = 0x11;
__attribute__((section(".fill6.second"), aligned(8))) char fill7_second = 0x22;

int main() { return 0; }
