#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xassembler -
.globl foo, bar
.data
.byte 0
foo:
.quad bar
EOF

cat <<EOF | $CC -o $t/b.o -c -xc -
extern int *foo;
int bar = 3;
int main() {}
EOF

! $CC --ld-path=./ld64 -o $t/exe $t/a.o $t/b.o -Wl,-fixup_chains >& $t/log
grep -Fq '/a.o(__DATA,__data): unaligned base relocation' $t/log
