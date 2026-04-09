#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe1 $t/a.o
otool -l $t/exe1 | grep -q 'stacksize 0$'

$CC --ld-path=./ld64 -o $t/exe2 $t/a.o -Wl,-stack_size,200000
otool -l $t/exe2 | grep -q 'stacksize 2097152$'
