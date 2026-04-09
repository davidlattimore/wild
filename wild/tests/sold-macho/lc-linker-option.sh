#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc - -fmodules
#include <zlib.h>
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o
