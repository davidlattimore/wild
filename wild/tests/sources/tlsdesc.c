// TODO: remove DiffIgnore for asm.* once relaxations are supported

//#AbstractConfig:default
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata

//#Config:gcc-tls-desc:default
//#CompArgs:-mtls-dialect=gnu2
//#LinkArgs:--cc=gcc -Wl,-z,now
//#Object:tlsdesc-obj.c

//#Config:gcc-tls-desc-pie:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIE

//#Config:gcc-tls-desc-shared:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC
//#Shared:tlsdesc-obj.c
//#DiffIgnore:asm.get_value

//#Config:clang-tls-desc:gcc-tls-desc
//#CompArgs:-mtls-dialect=gnu2
//#Compiler:clang

//#Config:clang-tls-desc-shared:clang-tls-desc
//#CompArgs:-mtls-dialect=gnu2 -fPIC
//#Shared:tlsdesc-obj.c
//#DiffIgnore:asm.get_value

int get_value();

int main()
{
    return get_value();
}
