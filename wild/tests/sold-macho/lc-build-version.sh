#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o
otool -l $t/exe | grep -q 'tool 54321'
