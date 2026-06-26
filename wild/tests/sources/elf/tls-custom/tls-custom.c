// Verifies that we can handle a custom, NOBITS TLS section.

//#SkipArch: ppc64le
//#LinkerDriver:gcc
//#Object:tls-custom-1.s
// GNU ld seems to have a bug as it overlaps the .tcustom and .tcustomdata sections,
// leading to non null-initialized data.
//#ReferenceLinkers:lld
//#LinkArgs:-Wl,--gc-sections
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
// At least some versions of GNU ld for risc-v export these symbols for some reason.
//#DiffIgnore:dynsym.tbss_a.section
//#DiffIgnore:dynsym.tcustom_a.section
//#DiffIgnore:section.got.plt.entsize
//#DiffIgnore:section.gnu.version_r.alignment
// Wild produces the same relaxations as GNU ld, only lld seems to diverge.
// It is probably best to ignore that difference.
//#DiffIgnore:rel.R_X86_64_32.R_X86_64_PC32
//#DiffMatchAny:true
//#ExpectProgramHeader:TLS mem-size=0x1000,file-size=0x800

extern __thread char tbss_a[1024];
extern __thread char tcustom_a[1024];
extern __thread char tcustomdata_a[2048];

int main() {
  if (tbss_a[0] != 0) {
    return 100;
  }
  if (tcustom_a[1023] != 0) {
    return 101;
  }
  if (tcustomdata_a[42] != 42) {
    return 104;
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
