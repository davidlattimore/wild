//#Config:function
//#ExpectError: undefined symbol: missing_host_fn

//#Config:data
//#CompArgs: -DTEST_DATA
//#ExpectError: undefined symbol: missing_data

//#Config:function-pic
//#CompArgs: -fPIC
//#ExpectError: undefined symbol: missing_host_fn

//#Config:data-pic
//#CompArgs: -DTEST_DATA -fPIC
//#ExpectError: undefined symbol: missing_data

// GC'd references to undefined symbols are not link errors.
//#Config:function-gc-dead
//#CompArgs: -DTEST_GC_DEAD
//#ExpectFuncImportCount: 0

//#Config:data-gc-dead
//#CompArgs: -DTEST_DATA -DTEST_GC_DEAD

//#Config:data-pic-gc-dead
//#CompArgs: -DTEST_DATA -DTEST_GC_DEAD -fPIC

//#Config:function-gc-dead-no-gc
//#CompArgs: -DTEST_GC_DEAD
//#LinkArgs: --no-gc-sections
//#ExpectError: undefined symbol: missing_host_fn

//#Config:data-gc-dead-no-gc
//#CompArgs: -DTEST_DATA -DTEST_GC_DEAD
//#LinkArgs: --no-gc-sections
//#ExpectError: undefined symbol: missing_data

//#Config:data-pic-gc-dead-no-gc
//#CompArgs: -DTEST_DATA -DTEST_GC_DEAD -fPIC
//#LinkArgs: --no-gc-sections
//#ExpectError: undefined symbol: missing_data

#ifdef TEST_DATA
extern int missing_data;

#ifdef TEST_GC_DEAD
void dead_function(void) { missing_data = 1; }

void _start(void) {}
#else
void _start(void) { missing_data = 1; }
#endif
#else
void missing_host_fn(void);

#ifdef TEST_GC_DEAD
void dead_function(void) { missing_host_fn(); }

void _start(void) {}
#else
void _start(void) { missing_host_fn(); }
#endif
#endif
