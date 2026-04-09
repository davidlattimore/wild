#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>
int main() {
  printf("Hello world\n");
}
EOF

$CC --ld-path=./ld64 -o $t/exe1 $t/a.o -Wl,-platform_version,macos,11,11
otool -l $t/exe1 > $t/log1
! grep -q LC_DYLD_CHAINED_FIXUPS %t/log1 || false

$CC --ld-path=./ld64 -o $t/exe2 $t/a.o -Wl,-platform_version,macos,13,13
otool -l $t/exe2 | grep -q LC_DYLD_CHAINED_FIXUPS
