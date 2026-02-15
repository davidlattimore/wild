#include <stdio.h>
#include <stdint.h>

// Define the symbol. It should override the linker provided one.
char __rela_iplt_start[16] __attribute__((section(".data"))) = "OVERRIDE";
char __rela_iplt_end[16] __attribute__((section(".data"))) = "OVERRIDE_END";

int main() {
    printf("Addr: %p\n", __rela_iplt_start);
    printf("Addr end: %p\n", __rela_iplt_end);
    return 0;
}
