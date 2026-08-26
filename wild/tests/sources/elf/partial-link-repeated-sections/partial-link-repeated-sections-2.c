const unsigned char foo_b __attribute__((section("foo"), used)) = 0x22;
const unsigned char bar_b __attribute__((section(".bar"), used)) = 0x44;
