//#Ignore:Archive directive not yet supported in macho test harness
//#Object:weak-vars-archive1.c

int __attribute__((weak)) value = 1;
int main() { return value; }
