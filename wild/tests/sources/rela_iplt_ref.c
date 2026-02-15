#include <stdio.h>
#include <stdint.h>

// Declare the symbol. It should be provided by the linker.
extern char __rela_iplt_start[];
extern char __rela_iplt_end[];

int main() {
    printf("Addr: %p\n", __rela_iplt_start);
    printf("Addr end: %p\n", __rela_iplt_end);
    return 0;
}
