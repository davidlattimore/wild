// A reference from a GC'd function is not a link error.
//#Config:data

//#Config:data-pic
//#CompArgs: -fPIC

//#Config:data-no-gc
//#LinkArgs: --no-gc-sections
//#ExpectError: undefined symbol: missing_data

//#Config:data-pic-no-gc
//#CompArgs: -fPIC
//#LinkArgs: --no-gc-sections
//#ExpectError: undefined symbol: missing_data

extern int missing_data;

void dead_function(void) { missing_data = 1; }

void _start(void) {}
