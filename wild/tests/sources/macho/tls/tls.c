//#Object:tls1.c

extern __thread int tls_var;
int get_tls(void);
int main() { return tls_var + get_tls(); }
