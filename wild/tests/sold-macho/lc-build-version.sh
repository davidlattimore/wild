#!/bin/bash
# shellcheck disable=SC2086,SC2046,SC2154,SC1091
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o
otool -l $t/exe | grep -qE 'tool (3|54321)'
