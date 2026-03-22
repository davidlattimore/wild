extern int data[];
int data[100];

extern __thread int tvar[];
__thread int tvar[100] __attribute__((common));
