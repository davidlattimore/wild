// Odd-sized data to misalign subsequent sections
const char padding[] =
    "abc";  // 4 bytes including NUL — ensures __data has odd alignment

__thread int tls_val = 0;
int get_tls(void) { return tls_val; }
