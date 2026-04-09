#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>

char msg[] = "Hello world\n";
char *p = msg;

int main() {
  printf("%s", p);
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o
$t/exe | grep -q 'Hello world'
