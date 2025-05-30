//#AbstractConfig:default
//#LinkArgs:-Wl,-z,now
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:dynsym._ZTIi.section
// TODO: Fix this. Note, it only shows up on openSUSE aarch64
//#DiffIgnore:rel.missing-copy-relocation.R_AARCH64_ABS64

//#Config:gcc:default
//#LinkerDriver:g++

//#Config:clang:default
//#Compiler:clang
//#LinkerDriver:clang++

#include <iostream>

void bar()
{
    throw 42;
}

void foo()
{
    bar();
}

int main()
{
    try
    {
        foo();
    }
    catch (int myNum)
    {
        std::cout << myNum << std::endl;
        return myNum;
    }

    return 1;
}
