#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>

int hello() {
  printf("Hello world\n");
  return 0;
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-e,_hello
$t/exe | grep -q 'Hello world'

! $CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-e,no_such_symbol 2> $t/log || false
grep -q 'undefined entry point symbol: no_such_symbol' $t/log
