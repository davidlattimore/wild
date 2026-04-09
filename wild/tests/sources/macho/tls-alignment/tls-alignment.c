// Tests that TLS variables are properly aligned when preceded by
// odd-sized data sections. The __thread_vars descriptors must be
// 8-byte aligned for dyld to process them correctly.
//#Object:tls-alignment1.c

extern __thread int tls_val;
int get_tls(void);

int main() {
  tls_val = 10;
  return get_tls() == 10 ? 42 : 1;
}
