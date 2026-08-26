// Test that partial linking merges sections with the same name.

//#Object:partial-link-repeated-sections-2.c
//#LinkArgs:-r
//#RunEnabled:false
//#ReferenceLinkers:bfd,lld
//#DiffEnabled:false
//#ExpectSectionBytes:foo=0x1122
//#ExpectSectionBytes:.bar=0x3344

const unsigned char foo_a __attribute__((section("foo"), used)) = 0x11;
const unsigned char bar_a __attribute__((section(".bar"), used)) = 0x33;
