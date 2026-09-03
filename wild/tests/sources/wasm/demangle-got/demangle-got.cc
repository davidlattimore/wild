//#AbstractConfig:base
//#CompArgs: -fPIC
//#Object:demangle-got2.cc
//#ExpectSection: name

//#Config:default:base
//#Contains: GOT.data.internal.Foo::value
//#DoesNotContain: GOT.data.internal._ZN3Foo5valueE

//#Config:no-demangle:base
//#LinkArgs: --no-demangle
//#Contains: GOT.data.internal._ZN3Foo5valueE
//#DoesNotContain: GOT.data.internal.Foo::value

//#Config:demangle:base
//#LinkArgs: --no-demangle --demangle
//#Contains: GOT.data.internal.Foo::value
//#DoesNotContain: GOT.data.internal._ZN3Foo5valueE

struct Foo {
  static int value;
};

extern "C" void _start() {
  if (Foo::value != 7) {
    __builtin_trap();
  }
}
