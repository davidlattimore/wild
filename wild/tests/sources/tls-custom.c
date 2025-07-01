// Verifies that we can handle a custom, NOBITS TLS section.

//#LinkerDriver:gcc
//#Object:tls-custom-1.s
//#EnableLinker:lld
//#LinkArgs:-Wl,--gc-sections
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
// At least some versions of GNU ld for risc-v export these symbols for some reason.
//#DiffIgnore:dynsym.tbss_a.section
//#DiffIgnore:dynsym.tcustom_a.section

extern __thread char tbss_a[1024];
extern __thread char tcustom_a[1024];

int main() {
    if (tbss_a[0] != 0) {
        return 100;
    }
    if (tcustom_a[1023] != 0) {
        return 101;
    }

    tbss_a[0] = 70;
    tcustom_a[1023] = 71;

    if (tbss_a[0] != 70) {
        return 102;
    }
    if (tcustom_a[1023] != 71) {
        return 103;
    }

    return 42;
}
