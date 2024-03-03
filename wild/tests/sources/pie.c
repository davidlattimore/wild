// A static-PIE binary. We're not using libc, so we need to locate and apply dynamic relocations in
// a similar way to what libc would do. One advantage of doing this rather than actually using libc
// is that we can give error codes when things aren't right that can help us debug what is wrong.

//#CompArgs:pie:-static -pie -fno-stack-protector -ftls-model=global-dynamic
//#LinkArgs:pie:-static -pie --no-dynamic-linker

#include "exit.h"
#include "init.h"
#include "init_tls.h"

#include <stdint.h>

#define NUM_DYN_TAGS 31
#define NUM_AUX 10

#define R_X86_64_RELATIVE 8

struct Dyn {
    uint64_t tag;
    uint64_t value;
};

struct Rela {
    uint64_t address;
    uint64_t info;
    uint64_t addend;
};

extern struct Dyn _DYNAMIC[];

static int value = 0;
static int value2 = 0;

// The constructor argument causes pointers to these functions to be placed in the .init_array
// section. These pointers need to be absolute pointers, which means we need to apply relocations to
// them.
void __attribute__ ((constructor)) premain() {
    value = 42;
}

void __attribute__ ((constructor)) premain2() {
    value2 = 10;
}

extern __thread long long int tvar1;

void _start_c(uint64_t* sp) {
    // Skip arguments
    int num_args = *sp;
    ++sp;
    if (num_args != 1) {
        exit_syscall(97);
    }
    sp += num_args;
    // There should be a null pointer after the arguments.
    if (*sp) {
        exit_syscall(98);
    }
    ++sp;

    // Skip env pointers
    while (*sp) {
        ++sp;
    }
    // Skip the null pointer at the end of the env pointers.
    ++sp;

    // Key auxilary vector entries by tag
    uint64_t aux_by_tag[NUM_AUX] = {};
    while (*sp) {
        uint64_t tag = *sp;
        sp++;
        uint64_t value = *sp;
        sp++;
        if (tag < NUM_AUX) {
            aux_by_tag[tag] = value;
        }
    }

    // Docs for aux tags: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/auxvec.h
    uint64_t base_address = aux_by_tag[7];
    if (!base_address) {
        uint64_t phdr = aux_by_tag[3];
        if (!phdr) {
            exit_syscall(99);
        }
        base_address = phdr & -4096;
    }

    if (!_DYNAMIC) {
        exit_syscall(100);
    }

    // Key dynamic table entries by tag.
    uint64_t by_tag[NUM_DYN_TAGS] = {};
    uint64_t flags1 = 0;
    for (struct Dyn* d = _DYNAMIC; d->tag != 0; d++) {
        if (d->tag < NUM_DYN_TAGS) {
            by_tag[d->tag] = d->value;
        } else if (d->tag == 0x000000006ffffffb) {
            flags1 = d->value;
        }
    }

    if (flags1 == 0) {
        exit_syscall(101);
    }

    struct Rela* rela = (struct Rela*)(by_tag[7] + base_address);
    int rela_size = by_tag[8];
    int rela_count = rela_size / sizeof(struct Rela);

    if (!rela) {
        exit_syscall(102);
    }
    if (!rela_count) {
        exit_syscall(103);
    }

    // Apply dynamic relocations.
    struct Rela* rela_end = rela + rela_count;
    for (; rela < rela_end; ++rela) {
        if (rela->info == R_X86_64_RELATIVE) {
            uint64_t* address = (uint64_t*)(rela->address + base_address);
            *address = base_address + rela->addend;
        } else {
            // Unsupported relocation type.
            exit_syscall(104);
        }
    }

    // Call our init functions, then make sure they ran by checking the values that they set.
    call_init_functions();
    if (value != 42) {
        exit_syscall(105);
    }
    if (value2 != 10) {
        exit_syscall(106);
    }

    // Initialise TLS, then do some basic checks that it works.
    int ret = init_tls(base_address);
    if (ret != 0) {
        exit_syscall(107);
    }

    if (tvar1 != 20) {
        exit_syscall(108);
    }

    exit_syscall(42);
}
