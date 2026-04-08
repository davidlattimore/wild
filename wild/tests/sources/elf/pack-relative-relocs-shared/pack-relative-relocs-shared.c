//#Config:wild-so
//#SoSingleLinker:wild
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now,-z,pack-relative-relocs
//#Shared:pack-relative-relocs-shared-1.c
//#DiffIgnore:section.rodata
//#DiffIgnore:rel.R_AARCH64_ADR_GOT_PAGE.R_AARCH64_ADR_GOT_PAGE
//#EnableLinker:lld

int foo(void);

int main() { return foo(); }
