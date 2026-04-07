//#Archive:lib.a:whole-archive1.c
//#LinkArgs:-all_load
//#LinkerDriver:clang

// Tests -all_load: forces all archive members to load, even unreferenced ones.
// whole-archive1.c defines get_value() which main calls.
// The main object does NOT reference get_value at compile time (it's extern).
// -all_load ensures the archive member is loaded regardless.
int get_value(void);
int main() { return get_value(); }
