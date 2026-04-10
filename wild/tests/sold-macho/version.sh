#!/bin/bash
# shellcheck disable=SC2086,SC2046,SC2154,SC1091
. $(dirname $0)/common.inc

./ld64 -v | grep -qEi 'wild|[ms]old'

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>

int main() {
  printf("Hello world\n");
}
EOF

$CC --ld-path=./ld64 -Wl,-v -o $t/exe $t/a.o | grep -qEi 'wild|[ms]old'
$t/exe | grep -q 'Hello world'
