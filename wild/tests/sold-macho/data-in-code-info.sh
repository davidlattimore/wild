#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe1 $t/a.o -Wl
otool -l $t/exe1 | grep -q DATA_IN_CODE

$CC --ld-path=./ld64 -o $t/exe2 $t/a.o -Wl,-data_in_code_info
otool -l $t/exe2 | grep -q DATA_IN_CODE

$CC --ld-path=./ld64 -o $t/exe3 $t/a.o -Wl,-no_data_in_code_info
otool -l $t/exe3 > $t/log3
! grep -q DATA_IN_CODE $t/log3 || false
