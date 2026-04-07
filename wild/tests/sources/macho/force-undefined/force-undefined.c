//#Ignore:-u flag not implemented for Mach-O
//#Object:force-undefined1.c
//#LinkArgs:-u _forced_sym

extern int forced_sym;
int main() { return forced_sym; }
