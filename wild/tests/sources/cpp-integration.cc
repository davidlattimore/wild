//#AbstractConfig:default
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data
//#DiffIgnore:section.sdata
//#DiffIgnore:section.rodata.alignment
//#DiffIgnore:section.bss.alignment
// On aarch64, GNU ld puts the copy relocation for this symbol in .data.rel.ro
// rather than .bss.
//#DiffIgnore:dynsym.__stack_chk_guard.section
//#Object:cpp-integration-2.cc

//#Config:pie:default
//#CompArgs:-fpie -fmerge-constants
//#LinkerDriver:g++
//#LinkArgs:-pie -Wl,-z,now
//#EnableLinker:lld

//#Config:no-pie:default
//#CompArgs:-fno-pie -fmerge-constants
//#LinkerDriver:g++
//#LinkArgs:-no-pie -Wl,-z,now
//#EnableLinker:lld

//#Config:clang-pie:default
//#CompArgs:-fpie
//#Compiler:clang
//#LinkerDriver:clang++
//#LinkArgs:-pie -Wl,-z,now
//#EnableLinker:lld

//#Config:model-large:default
//#CompArgs:-mcmodel=large
//#LinkerDriver:g++
//#LinkArgs:-Wl,-z,now
//#EnableLinker:lld
// TODO: Ubuntu: cc1plus: sorry, unimplemented: code model 'large' with '-fPIC'
//#Arch: x86_64

//#Config:clang-model-large:default
//#Compiler:clang
//#CompArgs:-mcmodel=large
//#LinkerDriver:clang++
//#LinkArgs:-Wl,-z,now
//#EnableLinker:lld
//#Arch: x86_64

//#Config:clang-crel:default
//#Compiler:clang
//#CompArgs: -Wa,--crel,--allow-experimental-crel
//#LinkerDriver:clang++
//#RequiresClangWithCrel:true
//#DiffEnabled:false
//#SkipLinker:ld

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
