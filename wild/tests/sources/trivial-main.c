//#AbstractConfig:default
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:section.data.alignment

//#Config:gcc:default

//#Config:gcc-static:default
//#LinkArgs:-static
//#DiffIgnore:section.rela.plt.link
//#DiffIgnore:section.sdata

//#Config:clang-static:default
//#Compiler:clang
//#LinkArgs:-static
//#DiffIgnore:section.rela.plt.link
//#DiffIgnore:section.sdata

//#Config:clang:default
//#Compiler: clang

int main()
{
    return 42;
}
