#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -shared -o $t/a.dylib -xc -
_Thread_local int b;
_Thread_local int c = 5;
EOF

cat <<EOF | $CC -o $t/b.o -c -xc -
#include <stdio.h>

int a = 3;
extern _Thread_local int b;
extern _Thread_local int c;

int main() {
  printf("%d %d %d\n", a, b, c);
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.dylib $t/b.o
$t/exe | grep -q '^3 0 5$'
