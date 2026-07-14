// Unresolved host imports keep the object's import module/name (WASI contract).
//#Contains: wasi_snapshot_preview1
//#DoesNotContain: __wasi_proc_exit

__attribute__((import_module("wasi_snapshot_preview1"), import_name("proc_exit"))) void proc_exit(
    int code);

void _start(void) { proc_exit(0); }
