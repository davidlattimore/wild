//#LinkerDriver:clang
//#Shared:shared-basic-lib.c

// Tests basic dylib creation and linking.
extern int get_value(void);
int main() { return get_value(); }
