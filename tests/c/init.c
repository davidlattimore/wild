typedef void (*init_fn_t)(void);

extern init_fn_t __init_array_start[];
extern init_fn_t __init_array_end[];
extern init_fn_t __preinit_array_start[];
extern init_fn_t __preinit_array_end[];

void call_init_functions(void) {
    int count = __preinit_array_end - __preinit_array_start;
    for (int i = 0; i < count; i++) {
        __preinit_array_start[i]();
    }
    count = __init_array_end - __init_array_start;
    for (int i = 0; i < count; i++) {
        __init_array_start[i]();
    }
}
