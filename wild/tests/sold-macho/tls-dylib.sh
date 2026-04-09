#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
_Thread_local int foo;
_Thread_local int bar = 5;
EOF

$CC --ld-path=./ld64 -shared -o $t/b.dylib $t/a.o

cat <<EOF | $CC -o $t/c.o -c -xc -
#include <stdio.h>

extern _Thread_local int foo;
extern _Thread_local int bar;

int main() {
  printf("%d %d\n", foo, bar);
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/c.o $t/b.dylib
$t/exe | grep -q '^0 5$'
