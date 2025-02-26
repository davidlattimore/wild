_Thread_local int global_tls1 = 1;

int foo() {
  return global_tls1;
}
