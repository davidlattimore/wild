#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-rpath,foo -Wl,-rpath,@bar
otool -l $t/exe > $t/log

grep -A3 'cmd LC_RPATH' $t/log | grep -q 'path foo'
grep -A3 'cmd LC_RPATH' $t/log | grep -q 'path @bar'
