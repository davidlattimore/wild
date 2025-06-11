//#AbstractConfig:default
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:section.data.alignment

//#Config:gcc:default

//#Config:gcc-static:default
//#LinkArgs:-static -Wl,--gc-sections
//#DiffIgnore:section.rela.plt.link
//#DiffIgnore:section.sdata

//#Config:gcc-static-pie-no-relax:default
//#CompArgs:-fPIE
//#LinkArgs:-static-pie -Wl,--gc-sections -Wl,--no-relax
//#DiffEnabled:false
//#SkipLinker:ld

//#Config:clang-static:default
//#Compiler:clang
//#LinkArgs:-static
//#DiffIgnore:section.rela.plt.link
//#DiffIgnore:section.sdata

//#Config:clang-static-pie-no-relax:default
//#Compiler:clang
//#CompArgs:-fPIE
//#LinkArgs:-static-pie -Wl,--gc-sections -Wl,--no-relax
//#DiffEnabled:false
//#SkipLinker:ld

//#Config:clang:default
//#Compiler: clang

int main()
{
    return 42;
}
