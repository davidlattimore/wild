#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>

static int foo[100];

int main() {
  foo[1] = 5;
  printf("%d %d %p\n", foo[0], foo[1], foo);
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o
$t/exe | grep -q '^0 5 '
