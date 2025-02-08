//#AbstractConfig:default
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata.alignment
//#DiffIgnore:section.bss.alignment
//#Object:cpp-integration-2.cc

//#Config:pie:default
//#CompArgs:-fpie -fmerge-constants
//#LinkArgs:--cc=g++ -pie -Wl,-z,now
//#EnableLinker:lld

//#Config:no-pie:default
//#CompArgs:-fno-pie -fmerge-constants
//#LinkArgs:--cc=g++ -no-pie -Wl,-z,now
//#EnableLinker:lld

//#Config:model-large:default
//#CompArgs:-mcmodel=large
//#LinkArgs:--cc=g++ -Wl,-z,now
//#EnableLinker:lld
//#Cross:false
// TODO: Ubuntu: cc1plus: sorry, unimplemented: code model 'large' with '-fPIC'
//#Arch: x86_64

#include <iostream>
#include <string>

const char* colon();
const char* char_c();
const char* char_d();

int main() {
    std::string foo;
    foo += "aaa";
    foo += colon();
    foo += "b";
    foo += ":";
    foo += char_c();
    foo += ":";
    foo += "d";
    if (foo != "aaa:b:c:d") {
        std::cout << foo << std::endl;
        return 10;
    }
    return 42;
}
