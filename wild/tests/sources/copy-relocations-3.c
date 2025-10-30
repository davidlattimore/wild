extern int s1;

int get_s1_pic(void) { return s1; }

__attribute__((aligned(0x100))) int aligned_int2;

unsigned long long ptr_to_int(void* ptr) { return (unsigned long long)ptr; }
