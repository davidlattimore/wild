//#AbstractConfig:base

//#Config:default:base
//#ExpectError: undefined symbol: Foo::missing\(\)

//#Config:no-demangle:base
//#LinkArgs: --no-demangle
//#ExpectError: undefined symbol: _ZN3Foo7missingEv

//#Config:demangle:base
//#LinkArgs: --no-demangle --demangle
//#ExpectError: undefined symbol: Foo::missing\(\)

struct Foo {
  void missing();
};

extern "C" void _start() {
  Foo foo;
  foo.missing();
}
