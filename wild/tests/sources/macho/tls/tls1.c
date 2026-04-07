__thread int tls_var = 20;
int get_tls(void) { return tls_var + 2; }
