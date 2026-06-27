static const char msg[] = "hi";

void _start(void) {
  if (msg[0] != 'h' || msg[1] != 'i' || msg[2] != '\0') {
    __builtin_trap();
  }
}
