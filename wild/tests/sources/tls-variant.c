//#AbstractConfig:default
//#LinkerDriver:gcc
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata
//#DiffIgnore:section.rodata.alignment

//#Config:gcc:default
//#CompArgs:-fpic
//#Object:tls-variant-1.c:-mtls-dialect=gnu2
//#Object:tls-variant-2.c:-ftls-model=global-dynamic 
//#Object:tls-variant-3.c:-ftls-model=initial-exec
//#Arch: x86_64

//#Config:gcc-shared:default
//#CompArgs:-fpic
//#Shared:tls-variant-1.c:-mtls-dialect=gnu2,tls-variant-2.c:-ftls-model=global-dynamic,tls-variant-3.c:-ftls-model=initial-exec
//#Arch: x86_64

int foo();
int bar();
int baz();

int main()
{
    if (foo() != 1) {
        return 1;
    }
    if (bar() != 1) {
        return 1;
    }
    if (baz() != 1) {
        return 1;
    }

    return 42;
}
