// TODO: remove DiffIgnore for asm.* once relaxations are supported

//#AbstractConfig:default
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata

//#Config:gcc-tls-desc:default
//#CompArgs:-mtls-dialect=gnu2
//#LinkArgs:--cc=gcc -Wl,-z,now
//#Object:tlsdesc-obj.c
//#Arch: x86_64

//#Config:gcc-tls-desc-aarch64:gcc-tls-desc
//#CompArgs:-mtls-dialect=desc
//#Arch: aarch64

//#Config:gcc-tls-desc-pie:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIE
//#Arch: x86_64

//#Config:gcc-tls-desc-pie-aarch64:gcc-tls-desc-pie
//#CompArgs:-mtls-dialect=desc
//#Arch: aarch64

//#Config:gcc-tls-desc-shared:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC
//#Shared:tlsdesc-obj.c
//#DiffIgnore:asm.get_value
//#Arch: x86_64

//#Config:gcc-tls-desc-shared-aarch64:gcc-tls-desc-shared
//#CompArgs:-mtls-dialect=desc
//#Arch: aarch64

//#Config:clang-tls-desc:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2
//#Compiler:clang
//#RequiresClangWithTlsDesc:true
//#Arch: x86_64

//#Config:clang-tls-desc-aarch64:clang-tls-desc
//#CompArgs:-mtls-dialect=desc
//#Arch: aarch64

//#Config:clang-tls-desc-shared:clang-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC
//#Shared:tlsdesc-obj.c
//#DiffIgnore:asm.get_value
//#Arch: x86_64

//#Config:clang-tls-desc-shared-aarch64:clang-tls-desc-shared
//#CompArgs:-mtls-dialect=desc
//#Arch: aarch64

int get_value();

int main()
{
    return get_value();
}
