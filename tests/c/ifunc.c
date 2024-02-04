#include <sys/types.h>

#include "exit.h"
#include "init.h"

typedef unsigned long long uint64_t;

extern int compute_value10(void);
extern int compute_value32(void);

struct Rela {
    size_t offset;
    size_t info;
    size_t addend;
};

typedef size_t (*ifunc_resolve_fn_t)(void);

const uint64_t R_X86_64_IRELATIVE = 37;

// Initialises ifuncs in a similar way to how glibc would do it if we were linking against it.
static int init_ifuncs(void) {
  extern const struct Rela __rela_iplt_start[];
  extern const struct Rela __rela_iplt_end[];
  for (const struct Rela *i = __rela_iplt_start; i < __rela_iplt_end; i++) {
    if ((i->info & 0xffffffff) != R_X86_64_IRELATIVE) {
        return 7;
    }
    size_t *offset = (void *) i->offset;
    ifunc_resolve_fn_t resolve_fn = (ifunc_resolve_fn_t)(i->addend);
    *offset = resolve_fn();
  }
  return 0;
}

extern int resolve_count;

typedef int (*vptr)(void);

const vptr v10_ptr = compute_value10;

void _start(void) {
    int rv = init_ifuncs();
    if (rv != 0) {
        exit_syscall(rv);
    }
    if (compute_value10() != 10) {
        exit_syscall(1);
    }
    if (compute_value32() != 32) {
        exit_syscall(2);
    }
    if (v10_ptr() != 10) {
        exit_syscall(3);
    }
    if (resolve_count != 2) {
        exit_syscall(4);
    }
    if (v10_ptr == compute_value32) {
        exit_syscall(5);
    }
    if (v10_ptr != compute_value10) {
        exit_syscall(5);
    }
    exit_syscall(42);
}
