// Make sure that we can link a shared object using a linker driver, and thus against crtend, where
// there's no executable code and thus no .eh_frame data except for what crtend likely contains.

//#AbstractConfig:default
//#Shared:shared.c
//#CompArgs:-fPIC
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:section.eh_frame.alignment
//#SkipArch:ppc64le

//#Config:gcc:default
//#LinkerDriver:gcc

//#Config:clang:default
//#LinkerDriver:clang

extern int foo;

int main(void) { return foo; }
