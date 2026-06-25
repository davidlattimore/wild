//#LinkerDriver:clang
//#SoSingleLinker:lld
//#Shared:foo.c
//#DiffIgnore:section.__unwind_info
//#DiffIgnore:section.__const

int foo(void);

int main() { return foo(); }
