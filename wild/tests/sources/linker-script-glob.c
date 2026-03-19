//#Mode:dynamic
//#RunEnabled:false
//#LinkArgs:-shared -z now -T ./linker-script-glob.ld
//#DiffIgnore:section.got
//#ExpectSym:val_0 section="mydata"
//#ExpectSym:val_1 section="mydata"
//#ExpectSym:val_5 section="mydata"
//#ExpectSym:val_9 section="mydata"
//#ExpectSym:val_A section="other"
//#ExpectSym:val_a section="other"
//#ExpectSym:val_underscore section="other"
//#ExpectSym:val_hello_world section="helloworld"
//#ExpectSym:val_hello_dash_world section="helloworld"
//#ExpectSym:val_hello_baz section="other"
//#DiffIgnore:section.riscv.attributes
//#DiffIgnore:segment.RISCV_ATTRIBUTES.*
// GNU ld emits `.riscv.attributes`, but Wild does not
//#DiffIgnore:riscv_attributes.*

static int val_0 __attribute__((used, section(".mydata.0"))) = 0;
static int val_1 __attribute__((used, section(".mydata.1"))) = 1;
static int val_5 __attribute__((used, section(".mydata.5"))) = 5;
static int val_9 __attribute__((used, section(".mydata.9"))) = 9;

static int val_A __attribute__((used, section(".mydata.A"))) = 10;
static int val_a __attribute__((used, section(".mydata.a"))) = 11;
static int val_underscore __attribute__((used, section(".mydata._"))) = 12;

static int val_hello_world __attribute__((used, section("hello_world"))) = 100;
static int val_hello_dash_world __attribute__((used, section("hello-world"))) =
    101;

static int val_hello_baz __attribute__((used, section("hello_baz"))) = 102;
