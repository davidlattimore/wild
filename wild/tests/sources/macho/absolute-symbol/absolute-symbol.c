//#RunEnabled:false
//#Ignore:ExpectSym directive not yet implemented in macho test harness

// Tests that absolute symbols (defined via assembly .set) are preserved.
// The ELF version uses: .set abs_sym, 0xCAFECAFE
// For C, we use an inline asm equivalent.

__asm__(".globl _abs_sym\n.set _abs_sym, 0xCAFE");

int main() { return 42; }
