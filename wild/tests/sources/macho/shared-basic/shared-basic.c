//#LinkerDriver:clang
//#Ignore:Dylib creation and -l linking not yet supported in test harness

extern int get_value(void);
int main() { return get_value(); }
