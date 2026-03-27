//#LinkArgs:-T ./linker-script-alignof-pass.ld
//#RunEnabled:false
//#DiffEnabled:false

__attribute__((section(".data.aligned"))) int aligned_data = 42;
void _start() {}
