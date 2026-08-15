//#Object:undefined-data-cross-object2.c
//#ExpectError: undefined symbol: missing_data

extern int missing_data;

void _start(void) { missing_data = 1; }
