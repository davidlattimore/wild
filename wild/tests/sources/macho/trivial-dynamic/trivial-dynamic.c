//#LinkerDriver:clang
//#Ignore:Dylib creation and -l linking not yet supported in test harness

extern int dyn_func(void);
int main() { return dyn_func(); }
