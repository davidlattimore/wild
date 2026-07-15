#include <string.h>

static const char greeting[] = "hello-from-archive";

const char* helper_greeting(void) { return greeting; }

int helper_answer(void) {
  if (strlen(greeting) != 18) {
    return -1;
  }
  return 42;
}
