#!/bin/bash
. $(dirname $0)/common.inc

[ "`uname -p`" = arm ] && { echo skipped; exit; }

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-headerpad,0
$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-headerpad,0x10000
