//#Config:wild-so
//#SoSingleLinker:wild
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now,-z,pack-relative-relocs
//#Shared:pack-relative-relocs-shared-1.c
//#DiffIgnore:section.rodata
// TODO: Enable linking with ld when fixing #1817
//#SkipLinker:ld

int foo(void);

int main() { return foo(); }
