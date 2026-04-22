#!/bin/bash
# Regression test: wild must discover the SDK via `xcrun --show-sdk-path`
# even when `-syslibroot` is not passed. Without this, `-lc++` silently
# resolves to nothing, wild defaults C++ symbol imports to libSystem,
# and dyld SIGABRT's at load with
#   Symbol not found: __ZTVN10__cxxabiv117__class_type_infoE
#
# This test invokes wild DIRECTLY (not via cc) to mimic the rustc
# codepath — rustc passes `-lc++` but never `-syslibroot`.
# Sibling sold-macho/*.sh use unquoted `$t/foo` throughout and the
# sandbox path is whitespace-free; the SC2086 noise on body $t/...
# expansions is suppressed below to match peers. The source line wraps
# the whole `$(dirname $0)/common.inc` in one set of quotes — defensive
# against a script path that contains spaces, without the nested-quote
# eyesore. SC1091 stays silenced because common.inc lives next to this
# script and shellcheck isn't run with -x.
# shellcheck disable=SC1091,SC2086,SC2154
. "$(dirname $0)/common.inc"

# Tiny C translation unit that references a libc++abi symbol.
# Just `main` with an extern reference is enough: wild must resolve
# the reference against libc++abi's exports (loaded via libc++.1.tbd
# through the -lc++ search path).
cat <<EOF | $CC -o $t/a.o -c -xc -
extern void* _ZTVN10__cxxabiv117__class_type_infoE;
int main(void) { return _ZTVN10__cxxabiv117__class_type_infoE ? 0 : 0; }
EOF

# Invoke wild directly — no cc wrapper, no -syslibroot. If SDK
# discovery doesn't kick in, the output binary will have only
# libSystem as a dylib dep and dyld will abort at load.
./ld64 $t/a.o -o $t/out -arch arm64 -platform_version macos 11.0.0 11.0.0 \
    -lc++ -lSystem -e _main

# Confirm libc++ ended up in LC_LOAD_DYLIB.
otool -L $t/out | grep -qi 'libc++'

# And the binary actually runs (dyld successfully resolves the C++ symbol).
$t/out
