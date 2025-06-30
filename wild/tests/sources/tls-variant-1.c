_Thread_local int global_tls1 = 1;

int foo(void) {
  return global_tls1;
}

// Ensure that TLS sections with custom names are placed correctly into the TLS segment.

_Thread_local int global_tls2 __attribute__ ((used, section (".second-tdata"))) = 1000;

_Thread_local int global_tls3 __attribute__ ((used, section (".second-tbss"))) = 0;

int get_global_tls2(void) {
  return global_tls2;
}

int get_global_tls3(void) {
  return global_tls3;
}

void set_global_tls3(int v) {
  global_tls3 = v;
}
