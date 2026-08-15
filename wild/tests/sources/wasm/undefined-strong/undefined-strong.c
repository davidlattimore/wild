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

#ifdef TEST_DATA
extern int missing_data;

void _start(void) { missing_data = 1; }
#else
void missing_host_fn(void);

void _start(void) { missing_host_fn(); }
#endif
