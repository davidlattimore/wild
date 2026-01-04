//#Mode:dynamic
//#RunEnabled:false
//#LinkArgs:-shared -z now -T ./linker-script.ld
//#DiffIgnore:section.got
//#ExpectDynSym:start_bar section="bar",offset-in-section=0
//#ExpectDynSym:start_aaa section="bar",offset-in-section=8
//#ExpectDynSym:end_bar section="bar",offset-in-section=12
//#ExpectSym:start_bar section="bar",offset-in-section=0
//#ExpectSym:start_aaa section="bar",offset-in-section=8
//#ExpectSym:end_bar section="bar",offset-in-section=12
//#ExpectSym:defsym_start_aaa section="bar"
//#ExpectSym:defsym_addr address=0x1234
//#ExpectSym:defsym_decimal address=0x123e
//#ExpectSym:defsym_hex address=0x1244
//#DiffIgnore:section.riscv.attributes
//#DiffIgnore:segment.RISCV_ATTRIBUTES.*

static int foo1 __attribute__((used, section(".data.foo"))) = 0x01;

static int baz1 __attribute__((used, section(".data.baz1"))) = 0x02;

static int aaa1 __attribute__((used, section(".data.aaa"))) = 0x03;
