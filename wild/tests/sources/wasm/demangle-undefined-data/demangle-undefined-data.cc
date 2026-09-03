//#AbstractConfig:base

//#Config:default:base
//#ExpectError: undefined symbol: Foo::missing_data

//#Config:no-demangle:base
//#LinkArgs: --no-demangle
//#ExpectError: undefined symbol: _ZN3Foo12missing_dataE

//#Config:demangle:base
//#LinkArgs: --no-demangle --demangle
//#ExpectError: undefined symbol: Foo::missing_data

struct Foo {
  static int missing_data;
};

extern "C" void _start() { Foo::missing_data = 1; }
