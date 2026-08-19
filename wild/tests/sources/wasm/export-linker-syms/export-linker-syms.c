// `--export` of linker-defined symbols.

//#Config:linker-globals
//#LinkArgs: --export=__wasm_call_ctors --export=__stack_pointer --export=__memory_base --export=__table_base --export=__heap_base --export=__data_end --export=__global_base --export=__dso_handle --export=__heap_end --export=__wasm_first_page_end
//#ExpectSym: __wasm_call_ctors
//#ExpectSym: __stack_pointer
//#ExpectSym: __memory_base address=0
//#ExpectSym: __table_base
//#ExpectSym: __heap_base
//#ExpectSym: __data_end
//#ExpectSym: __global_base
//#ExpectSym: __dso_handle
//#ExpectSym: __heap_end
//#ExpectSym: __wasm_first_page_end
//#ExpectSym: _start

//#Config:export-if-defined
//#LinkArgs: --export-if-defined=__wasm_call_ctors --export-if-defined=__stack_pointer --export-if-defined=__heap_base
//#ExpectSym: __wasm_call_ctors
//#ExpectSym: __stack_pointer
//#ExpectSym: __heap_base
//#ExpectSym: _start

//#Config:no-entry
//#LinkArgs: --no-entry --export=__wasm_call_ctors
//#RunEnabled: false
//#ExpectSym: __wasm_call_ctors
//#NoSym: _start

//#Config:tls-base
//#LinkArgs: --export=__tls_base
//#ExpectError: symbol exported via --export not found: __tls_base

//#Config:tls-base-if-defined
//#LinkArgs: --export-if-defined=__tls_base
//#NoSym: __tls_base
//#ExpectSym: _start

void _start(void) {}
