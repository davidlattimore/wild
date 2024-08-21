//#AbstractConfig:default
//#LinkArgs:--cc=gcc
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:.got.plt

//#Config:gcc:default

//#Config:clang:default
//#Compiler: clang

int main()
{
    return 42;
}
