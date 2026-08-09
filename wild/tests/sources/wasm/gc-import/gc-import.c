// Unreferenced host imports (and the only local that uses them) are GC'd. Live imports referenced
// from a live function remain.

//#Config:default-gc
//#RunEnabled: false
//#ExpectFuncImport: env/gc_host_keep=1
//#ExpectFuncImport: env/gc_host_dead=0
//#ExpectFuncImportCount: 1
//#DoesNotContain: gc_only_uses_dead_host

//#Config:no-gc-sections
//#LinkArgs: --no-gc-sections
//#RunEnabled: false
//#ExpectFuncImport: env/gc_host_keep=1
//#ExpectFuncImport: env/gc_host_dead=1
//#ExpectFuncImportCount: 2
//#Contains: gc_only_uses_dead_host

__attribute__((import_module("env"), import_name("gc_host_keep"))) void gc_host_keep(void);
__attribute__((import_module("env"), import_name("gc_host_dead"))) void gc_host_dead(void);

void gc_only_uses_dead_host(void) { gc_host_dead(); }

void _start(void) { gc_host_keep(); }
