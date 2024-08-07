//#AbstractConfig:default
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata.alignment
//#Object:cpp-integration-2.cc

//#Config:pie:default
//#CompArgs:-fpie -fmerge-constants
//#LinkArgs:--cc=g++ -pie -Wl,-z,now

//#Config:no-pie:default
//#CompArgs:-fno-pie -fmerge-constants
//#LinkArgs:--cc=g++ -no-pie -Wl,-z,now

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
