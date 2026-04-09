#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>
int main() {
  printf("Hello world\n");
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o
cp $t/exe $t/exe1

$CC --ld-path=./ld64 -o $t/exe $t/a.o
cp $t/exe $t/exe2

diff $t/exe1 $t/exe2
