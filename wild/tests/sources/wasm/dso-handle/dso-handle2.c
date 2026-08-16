extern char __global_base;

unsigned long global_base_from_other_tu(void) { return (unsigned long)&__global_base; }
