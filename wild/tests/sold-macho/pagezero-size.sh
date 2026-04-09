#!/bin/bash
. $(dirname $0)/common.inc

[ "`uname -p`" = arm ] && { echo skipped; exit; }

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>
int main() {
  printf("Hello world\n");
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o

otool -l $t/exe | grep -A5 'segname __PAGEZERO' | \
  grep -q 'vmsize 0x0000000100000000'

$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-pagezero_size,0x10000
$t/exe | grep -q 'Hello world'

otool -l $t/exe | grep -A5 'segname __PAGEZERO' | \
  grep -q 'vmsize 0x0000000000010000'
