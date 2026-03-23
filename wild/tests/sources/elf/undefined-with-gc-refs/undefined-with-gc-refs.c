// Verifies that we report undefined symbol errors when there are multiple
// objects referencing the undefined symbol, but the canonical reference gets
// GCed. The canonical undefined symbol has at different points been either the
// first or last reference, so we make sure both get GCed.

//#CompArgs:-ffunction-sections
//#LinkArgs:--gc-sections
//#Object:undefined-with-gc-refs-1.c
//#Object:undefined-with-gc-refs-2.c
//#Object:undefined-with-gc-refs-3.c
//#ExpectError:foo

void ref_2(void);

void _start(void) { ref_2(); }
