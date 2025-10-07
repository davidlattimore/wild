//#Mode:dynamic
//#LinkArgs:-shared -z now -T ./linker-script.ld
//#DiffIgnore:section.got
//#ExpectDynSym:start_bar bar 0
//#ExpectDynSym:start_aaa bar 8
//#ExpectDynSym:end_bar bar 12
//#ExpectSym:start_bar bar 0
//#ExpectSym:start_aaa bar 8
//#ExpectSym:end_bar bar 12
//#DiffIgnore:section.riscv.attributes
//#DiffIgnore:segment.SHT_RISCV_ATTRIBUTES.*

static int foo1 __attribute__((used, section(".data.foo"))) = 0x01;

static int baz1 __attribute__((used, section(".data.baz1"))) = 0x02;

static int aaa1 __attribute__((used, section(".data.aaa"))) = 0x03;
