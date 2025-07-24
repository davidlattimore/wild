//#AbstractConfig:default
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata
//#DiffIgnore:dynsym.foo.section

//#Config:gcc:default
//#CompArgs:-ftls-model=local-dynamic -fPIC -O2
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now

//#Config:gcc-no-relax:gcc
//#LinkArgs:-Wl,-z,now,--no-relax
//#DiffEnabled:false

//#Config:gcc-no-relax-aarch64:gcc-no-relax
//#CompArgs:-ftls-model=local-dynamic -fPIC -O2 -mtls-dialect=trad
//#Arch:aarch64

_Thread_local long foo = 42;

int main() { return foo; }
