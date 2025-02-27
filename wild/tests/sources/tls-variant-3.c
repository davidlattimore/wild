extern _Thread_local int global_tls1;

int baz() {
  return global_tls1;
}
