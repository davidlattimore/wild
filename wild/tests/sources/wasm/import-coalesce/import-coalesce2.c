__attribute__((import_module("wasi_snapshot_preview1"), import_name("proc_exit"))) void proc_exit(
    int code);

void helper(void) { proc_exit(1); }
