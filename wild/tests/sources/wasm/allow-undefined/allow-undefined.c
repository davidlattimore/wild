//#Config:function
//#LinkArgs: --allow-undefined
//#RunEnabled: false
//#ExpectFuncImport: env/missing_host_fn=1
//#ExpectFuncImportCount: 1

//#Config:data
//#CompArgs: -DTEST_DATA
//#LinkArgs: --allow-undefined
//#RunEnabled: false
//#ExpectFuncImportCount: 0

//#Config:function-pic
//#CompArgs: -fPIC
//#LinkArgs: --allow-undefined
//#RunEnabled: false
//#ExpectFuncImport: env/missing_host_fn=1
//#ExpectFuncImportCount: 1

//#Config:data-pic
//#CompArgs: -DTEST_DATA -fPIC
//#LinkArgs: --allow-undefined
//#RunEnabled: false
//#ExpectFuncImportCount: 0

#ifdef TEST_DATA
extern int missing_data;

void _start(void) { missing_data = 1; }
#else
void missing_host_fn(void);

void _start(void) { missing_host_fn(); }
#endif
