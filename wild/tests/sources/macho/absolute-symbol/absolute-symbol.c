//#RunEnabled:false
//#ExpectSym:abs_sym
//#Ignore:LC_SYMTAB not yet emitted for executables

// Tests that absolute symbols (defined via assembly .set) are preserved.
__asm__(".globl _abs_sym\n.set _abs_sym, 0xCAFE");

int main() { return 42; }
