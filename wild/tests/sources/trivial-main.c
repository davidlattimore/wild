//#AbstractConfig:default
//#LinkArgs:--cc=gcc -Wl,-z,now
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data

//#Config:clang:default
//#Compiler: clang

int main()
{
    return 42;
}
