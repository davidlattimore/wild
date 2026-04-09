#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>

int main() {
  printf("Hello");
  fprintf(stdout, " world\n");
  fprintf(stderr, "Hello stderr\n");
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o
$t/exe 2> /dev/null | grep -q 'Hello world'
$t/exe 2>&1 > /dev/null | grep -q 'Hello stderr'
