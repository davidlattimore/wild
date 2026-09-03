//#AbstractConfig:base
//#ExpectSection: name

// Default is `--demangle`.
//#Config:default:base
//#Contains: Foo::bar()
//#DoesNotContain: _ZN3Foo3barEv

//#Config:no-demangle:base
//#LinkArgs: --no-demangle
//#Contains: _ZN3Foo3barEv
//#DoesNotContain: Foo::bar()

//#Config:demangle:base
//#LinkArgs: --no-demangle --demangle
//#Contains: Foo::bar()
//#DoesNotContain: _ZN3Foo3barEv

// Single-dash form used by `clang -Wl,-no-demangle`.
//#Config:single-dash-no-demangle:base
//#LinkArgs: -no-demangle
//#Contains: _ZN3Foo3barEv
//#DoesNotContain: Foo::bar()

//#Config:undefined:base
//#CompArgs: -DUNDEFINED
//#ExpectError: undefined symbol: Foo::missing\(\)

//#Config:undefined-no-demangle:base
//#CompArgs: -DUNDEFINED
//#LinkArgs: --no-demangle
//#ExpectError: undefined symbol: _ZN3Foo7missingEv

//#Config:undefined-demangle:base
//#CompArgs: -DUNDEFINED
//#LinkArgs: --no-demangle --demangle
//#ExpectError: undefined symbol: Foo::missing\(\)

struct Foo {
  Foo();
  void bar();
  void missing();
};

Foo::Foo() {}

void Foo::bar() {}

extern "C" void _start() {
  Foo foo;
#ifdef UNDEFINED
  foo.missing();
#else
  foo.bar();
#endif
}
