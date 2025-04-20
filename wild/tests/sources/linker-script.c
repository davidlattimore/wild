//#LinkerScript:linker-script.ld
//#Static:false
//#LinkArgs:-shared -z now
//#RunEnabled:false
//#DiffIgnore:section.got
//#ExpectDynSym:start_bar bar 0
//#ExpectDynSym:start_aaa bar 8
//#ExpectDynSym:end_bar bar 12

static int foo1 __attribute__ ((used, section (".data.foo"))) = 0x01;

static int baz1 __attribute__ ((used, section (".data.baz1"))) = 0x02;

static int aaa1 __attribute__ ((used, section (".data.aaa"))) = 0x03;
