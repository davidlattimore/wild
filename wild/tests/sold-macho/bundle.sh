#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>
void hello() {
  printf("Hello world\n");
}
EOF

$CC --ld-path=./ld64 -o $t/bundle $t/a.o -Wl,-bundle
file $t/exe | grep -qi bundle
