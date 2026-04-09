#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>
void hello() {
  printf("Hello world\n");
}
EOF

cat <<EOF | $CC -o $t/b.o -c -xc -
void hello();
int main() {
  hello();
}
EOF

$CC -o $t/exe $t/a.o $t/b.o -Wl,-bind_at_load -Wl,-no_fixup_chains
$t/exe | grep -q 'Hello world'
objdump --macho --lazy-bind $t/exe > $t/log
! grep -q _hello $t/log || false
