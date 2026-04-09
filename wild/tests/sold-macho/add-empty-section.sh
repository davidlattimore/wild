#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-add_empty_section,__FOO,__foo

otool -l $t/exe | grep -q 'segname __FOO'
otool -l $t/exe | grep -q 'sectname __foo'
