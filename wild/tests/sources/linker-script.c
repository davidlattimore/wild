//#LinkerScript:linker-script.ld
//#Static:false
//#LinkArgs:-shared -z now
//#RunEnabled:false
//#DiffIgnore:section.got

static int foo1 __attribute__ ((used, section (".data.foo"))) = 1;

static int baz1 __attribute__ ((used, section (".data.baz1"))) = 10;
