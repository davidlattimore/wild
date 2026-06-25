//#Config:wild-so
//#SkipArch: ppc64le
//#SoSingleLinker:wild
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now,-z,pack-relative-relocs
//#Shared:pack-relative-relocs-shared-1.c
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:rel.R_AARCH64_ADR_GOT_PAGE.R_AARCH64_ADR_GOT_PAGE
//#ReferenceLinkers:bfd,lld
//#DiffMatchAny:true

int foo(void);

int main() { return foo(); }
