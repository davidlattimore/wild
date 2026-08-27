//#LinkArgs:-T ./linker-script-alignof-pass.ld
//#RunEnabled:false
//#DiffEnabled:false
//#ExpectSym:aligned_data alignment=2048

__attribute__((section(".data.aligned"))) int aligned_data = 42;
void _start() {}
