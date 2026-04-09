#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>

int main();

void print() {
  printf("%d\n", (char *)print < (char *)main);
}

int main() {
  print();
}
EOF

cat <<EOF > $t/order1
_print
_main
EOF

cat <<EOF > $t/order2
_main
_print
EOF

$CC --ld-path=./ld64 -o $t/exe1 $t/a.o -Wl,-order_file,$t/order1
$t/exe1 | grep -q '^1$'

$CC --ld-path=./ld64 -o $t/exe2 $t/a.o -Wl,-order_file,$t/order2
$t/exe2 | grep -q '^0$'
