//#Object:import-coalesce2.c
//#RunEnabled: false
//#DiffEnabled: false
//#ExpectFuncImport: wasi_snapshot_preview1/proc_exit=1
//#ExpectFuncImportCount: 1

__attribute__((import_module("wasi_snapshot_preview1"), import_name("proc_exit"))) void proc_exit(
    int code);

void helper(void);

void _start(void) {
  helper();
  proc_exit(0);
}
