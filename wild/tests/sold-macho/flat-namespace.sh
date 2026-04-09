#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>
void hello() { printf("Hello world\n"); }
void foo() { hello(); }
EOF

$CC --ld-path=./ld64 -shared -o $t/b.dylib $t/a.o -Wl,-flat_namespace

objdump --macho --bind --lazy-bind $t/b.dylib | grep -Eq 'flat-namespace\s+_hello'
objdump --macho --bind --lazy-bind $t/b.dylib | grep -Eq 'flat-namespace\s+_printf'

cat <<EOF | $CC -o $t/c.o -c -xc -
#include <stdio.h>
void hello() { printf("interposed\n"); }
EOF

$CC --ld-path=./ld64 -shared -o $t/d.dylib $t/c.o

cat <<EOF | $CC -o $t/e.o -c -xc -
#include <stdio.h>
void foo();
int main() { foo(); }
EOF

$CC --ld-path=./ld64 -o $t/exe $t/e.o $t/d.dylib $t/b.dylib
$t/exe | grep -q interposed
