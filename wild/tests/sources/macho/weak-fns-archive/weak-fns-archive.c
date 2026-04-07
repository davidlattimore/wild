//#Ignore:Archive directive not yet supported in macho test harness
//#Object:weak-fns-archive1.c

int __attribute__((weak)) get_value(void) { return 1; }
int main() { return get_value(); }
