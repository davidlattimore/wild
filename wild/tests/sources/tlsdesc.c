// TODO: remove DiffIgnore for asm.* once relaxations are supported

//#AbstractConfig:default
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata

//#Config:gcc-tls-desc:default
//#CompArgs:-mtls-dialect=gnu2 -fPIC -O2
//#LinkerDriver:gcc
//#LinkArgs:-Wl,-z,now
//#Object:tlsdesc-obj.c
//#Arch: x86_64

//#Config:gcc-tls-desc-desc:gcc-tls-desc
//#CompArgs:-mtls-dialect=desc -fPIC
//#SkipArch: x86_64,riscv64

//#Config:gcc-tls-desc-pie:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIE
//#Arch: x86_64

//#Config:gcc-tls-desc-pie-desc:gcc-tls-desc-pie
//#CompArgs:-mtls-dialect=desc
//#SkipArch: x86_64,riscv64

//#Config:gcc-tls-desc-static:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC -static
//#Shared:tlsdesc-obj.c
//#DiffIgnore:asm.get_value
//#Arch: x86_64

//#Config:gcc-tls-desc-shared:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC
//#Shared:tlsdesc-obj.c
//#Arch: x86_64

//#Config:gcc-tls-desc-shared-desc:gcc-tls-desc-shared
//#CompArgs:-mtls-dialect=desc
//#SkipArch: x86_64,riscv64

//#Config:clang-tls-desc:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC
//#Compiler:clang
//#RequiresCompilerFlags:-mtls-dialect=gnu2
//#Arch: x86_64

//#Config:clang-tls-desc-desc:clang-tls-desc
//#CompArgs:-mtls-dialect=desc -fPIC
//#SkipArch: x86_64,riscv64

//#Config:clang-tls-desc-shared:clang-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC
//#Shared:tlsdesc-obj.c
//#Arch: x86_64

//#Config:clang-tls-desc-shared-desc:clang-tls-desc-shared
//#CompArgs:-mtls-dialect=desc -fPIC
//#SkipArch: x86_64,riscv64

int get_value();

int main() { return get_value(); }
