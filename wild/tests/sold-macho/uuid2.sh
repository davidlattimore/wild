#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -c -o $t/a.o -xc -
#include <stdio.h>

int main() {
  printf("Hello world\n");
}
EOF

$CC --ld-path=./ld64 -B. -o $t/exe1 $t/a.o -Wl,-adhoc_codesign
$CC --ld-path=./ld64 -B. -o $t/exe2 $t/a.o -Wl,-adhoc_codesign

[ "$(otool -l $t/exe1 | grep 'uuid ')" != "$(otool -l $t/exe2 | grep 'uuid ')" ]
