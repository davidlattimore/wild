//#AbstractConfig:default
//#Object:tls1.c
//#Object:init_tls.c
//#Object:exit.c

//#Config:global-dynamic-0:default
//#CompArgs:-ftls-model=global-dynamic
//#Variant: 0

//#Config:global-dynamic-1:global-dynamic-0
//#Variant: 1

//#Config:local-dynamic-0:default
//#CompArgs:-ftls-model=local-dynamic
//#Variant: 0

//#Config:local-dynamic-1:local-dynamic-0
//#Variant: 1

//#Config:initial-exec:default
//#CompArgs:-ftls-model=initial-exec

//#Config:local-exec:default
//#CompArgs:-ftls-model=local-exec

#include "exit.h"
#include "init_tls.h"

#include <stddef.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint64_t u64;

extern __thread int tvar1;
__thread long long int tvar2 = 20;
__thread char tvar3 = 12;

// Make sure we have a couple of zero-initialised variables, since they go into TBSS rather than
// TDATA.
__thread int tvar4 = 0;
static __thread int tvar5 = 0;
__thread char tvar6 = 0;

void _start(void) {
    int ret = init_tls(0);
    if (ret != 0) {
        exit_syscall(ret);
    }
    exit_syscall(tvar1 + tvar2 + tvar3 + tvar4 + tvar5 + tvar6);
}

u8*** get_tcb(void);

// When statically linking, glibc doesn't provide __tls_get_addr, however musl does. So we need to
// make sure we work in either case.

#if VARIANT == 1
void* __tls_get_addr(size_t* mod_and_offset) {
    size_t mod = mod_and_offset[0];
    size_t offset = mod_and_offset[1];
    u8*** tcb = get_tcb();
    u8** modules = tcb[1];
    u8* module_data = modules[mod];
    return &module_data[offset];
}
#endif
