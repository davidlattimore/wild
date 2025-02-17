//#AbstractConfig:default
//#LinkArgs:--cc=gcc -Wl,-z,now
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data

//#Config:gcc:default

//#Config:clang:default
//#Compiler: clang

int main()
{
    return 42;
}
