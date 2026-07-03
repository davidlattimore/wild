//#AbstractConfig:default
//#LinkerDriver:clang
//#SoSingleLinker:lld
//#DiffIgnore:section.__unwind_info
//#DiffIgnore:section.__const

//#Config:dylib:default
//#TestUpdateInPlace:true
//#Shared:foo.c

//#Config:fat-dylib:default
//#FatDylib:foo.c

//#Config:fat-dylib64:default
// lld doesn't support fat64
//#ReferenceLinkers:
//#FatDylib64:foo.c

int foo(void);

int main() { return foo(); }
