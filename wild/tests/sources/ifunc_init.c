#include <sys/types.h>
#include <stdint.h>

#include "ifunc_init.h"

struct Rela {
    size_t offset;
    size_t info;
    size_t addend;
};

typedef size_t (*ifunc_resolve_fn_t)(void);

const uint64_t R_X86_64_IRELATIVE = 37;

// Initialises ifuncs in a similar way to how glibc would do it if we were linking against it.
int init_ifuncs(void) {
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
