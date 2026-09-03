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

struct Foo {
  Foo();
  void bar();
};

Foo::Foo() {}

void Foo::bar() {}

extern "C" void _start() {
  Foo foo;
  foo.bar();
}
