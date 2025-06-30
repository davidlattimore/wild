//#AbstractConfig:default
//#LinkerDriver:gcc
//#DiffIgnore:.dynamic.DT_NEEDED
//#DiffIgnore:section.data
//#DiffIgnore:section.rodata
//#DiffIgnore:section.rodata.alignment
//#DiffIgnore:rel.match_failed.R_AARCH64_TLSGD_ADR_PAGE21

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

//#Config:gcc-aarch64:default
//#CompArgs:-fpic
//#Object:tls-variant-1.c
//#Object:tls-variant-2.c:-ftls-model=global-dynamic -mtls-dialect=trad
//#Object:tls-variant-3.c:-ftls-model=initial-exec -mtls-dialect=trad
//#Arch: aarch64

//#Config:gcc-shared-aarch64:default
//#CompArgs:-fpic
//#Shared:tls-variant-1.c,tls-variant-2.c:-ftls-model=global-dynamic -mtls-dialect=trad,tls-variant-3.c:-ftls-model=initial-exec -mtls-dialect=trad
//#Arch: aarch64
// Similarly to Mold, Wild also sets STATIC_TLS flag.
//#DiffIgnore:.dynamic.DT_FLAGS.STATIC_TLS

int foo(void);
int bar(void);
int baz(void);
int get_global_tls2(void);
int get_global_tls3(void);
void set_global_tls3(int v);

int main()
{
    if (foo() != 1) {
        return 1;
    }
    if (bar() != 1) {
        return 2;
    }
    if (baz() != 1) {
        return 3;
    }
    if (get_global_tls2() != 1000) {
        return 4;
    }
    if (get_global_tls3() != 0) {
        return 5;
    }
    set_global_tls3(19);
    if (get_global_tls3() != 19) {
        return 5;
    }

    return 42;
}
