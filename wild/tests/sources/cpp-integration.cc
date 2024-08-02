//#AbstractConfig:default
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data

//#Config:pie:default
//#CompArgs:-fpie
//#LinkArgs:--cc=g++ -pie -Wl,-z,now

//#Config:no-pie:default
//#CompArgs:-fno-pie
//#LinkArgs:--cc=g++ -no-pie -Wl,-z,now

#include <iostream>

int main() {
    std::cout << std::endl;
    return 42;
}
