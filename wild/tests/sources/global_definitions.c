//#Object:global_references.c
//#Object:runtime.c
//#EnableLinker:lld

int global_value = 38;
int global_values[4] = {1, 2, 3, 4};

asm(
    ".globl abs1\n\
    .set abs1, 25\n");
