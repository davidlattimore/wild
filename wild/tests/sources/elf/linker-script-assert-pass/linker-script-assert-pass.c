//#LinkArgs:-T ./linker-script-assert-pass.ld
//#RunEnabled:false
//#DiffEnabled:false
void _start() {}

int symbol4 = 0x4000;
int symbol6 __attribute__((weak));
int symbol7 __attribute__((weak)) = 0x7000;
extern int symbol8 __attribute__((weak));
extern int symbol9;
