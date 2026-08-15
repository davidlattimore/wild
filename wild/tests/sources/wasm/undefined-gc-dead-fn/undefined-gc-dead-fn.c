//#Config:default
//#ExpectFuncImportCount: 0

//#Config:no-gc
//#LinkArgs: --no-gc-sections
//#ExpectError: undefined symbol: missing_host_fn

void missing_host_fn(void);

void dead_function(void) { missing_host_fn(); }

void _start(void) {}
