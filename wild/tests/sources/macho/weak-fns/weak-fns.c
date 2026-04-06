//#Object:weak-fns1.c

int __attribute__((weak)) get_value(void) { return 1; }
int main() { return get_value(); }
