#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
double pi1() { return 3.1415926535; }
EOF

cat <<EOF | $CC -o $t/b.o -c -xc -
double pi2() { return 3.1415926535; }
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o $t/b.o
objdump -h $t/exe | grep -Eq ' __literal8\s+00000008\s'
