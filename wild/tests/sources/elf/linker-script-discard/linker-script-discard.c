//#Mode:dynamic
//#RunEnabled:false
//#LinkArgs:-shared -z now -T ./linker-script-discard.ld
//#ExpectSym:keep_symbol section="keep"
//#NoSym:drop_symbol

int keep_symbol __attribute__((used, section(".data.keep"))) = 7;
static int drop_symbol __attribute__((used, section(".data.drop"))) = 9;
