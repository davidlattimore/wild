static int other __attribute__((used, section("__DATA,__custom"))) = 12;

int get_custom_value(void) { return other; }
