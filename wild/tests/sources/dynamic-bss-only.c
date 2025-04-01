// This test sets up the scenario where we have TBSS, but not TDATA. We then have a TLSGD relocation
// for a local TLS variable in TBSS. We hope to verify that the TLSGD entry gets the correct offset.

//#CompArgs:-fPIC -ftls-model=global-dynamic
//#LinkArgs:-shared -z now
//#RunEnabled:false
//#DiffIgnore:.dynamic.DT_RELAENT
//#DiffIgnore:.dynamic.DT_RELA

// We use a large alignment here so that it's almost certain that padding will need to be added
// before our TLS segment, which could cause us to compute incorrect offsets if we used the address
// of the non-existent TDATA section as the start of TLS.
__attribute__ ((aligned(256)))
static __thread long int tvar1;

long int get_tvar1(void) {
    return tvar1;
}

void set_tvar1(long int value) {
    tvar1 = value;
}
