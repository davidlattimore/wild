//#CompArgs:-fcommon
//#Object:common-shared-1.c
//#LinkArgs:-shared -z now
//#RunEnabled:false
//#DiffIgnore:section.got
//#ExpectSym:data section=".bss",size=400
//#ExpectDynSym:data section=".bss",size=400
//#ExpectSym:tvar section=".tbss",size=400,address=0
//#ExpectDynSym:tvar section=".tbss",size=400,address=0

extern int data[];
int data[10];

extern __thread int tvar[];
__thread int tvar[10] __attribute__((common));
