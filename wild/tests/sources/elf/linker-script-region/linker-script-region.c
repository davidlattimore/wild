//#AbstractConfig:default
//#RunEnabled:false
//#LinkArgs:-shared
//#EnableLinker: lld
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW

//#Config:regions:default
//#LinkerScript:linker-script-region.ld
//#ExpectProgramHeader:LOAD flags=RW,sections=[.data.ram1,.data.ram2,*]
//#ExpectProgramHeader:LOAD flags=RW,sections=[.data.ram3,*]
//#ExpectProgramHeader:LOAD sections=[.data.rom,*]
//#ExpectSym:var1 address=0x10000000
//#ExpectSym:var3 address=0x10000004
//#ExpectSym:var4 address=0x10000010

//#Config:region-redefine:default
// GNU ld only prints a warning.
//#SkipLinker:ld
//#LinkerScript:linker-script-region.ld
//#LinkerScript:linker-script-region-redefine.ld
//#ExpectError:region 'ROM' already defined

//#Config:region-missing:default
// GNU ld only prints a warning.
//#SkipLinker:ld
//#LinkerScript:linker-script-region-missing.ld
//#ExpectError:(?i)memory region 'FLASH' not declared

//#Config:region-overflow:default
// lld gives a similar error, but with a different message.
//#SkipLinker:lld
//#LinkerScript:linker-script-region-overflow.ld
//#ExpectError:(?i)region .FLASH' overflowed by 1 byte

static int var1 __attribute__((used, section(".data.ram1"))) = 0x01;
static int var2 __attribute__((used, section(".data.rom"))) = 0x02;
static int var3 __attribute__((used, section(".data.ram2"))) = 0x03;
static int var4 __attribute__((used, section(".data.ram3"))) = 0x04;
static int var5 __attribute__((used, section(".data.flash"))) = 0x05;

void _start(void) {}
