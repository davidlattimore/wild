#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -c -o $t/a.o -xc -
int a = 1;
EOF

$CC --ld-path=./ld64 -shared -o $t/b.so $t/a.o

cat <<EOF | $CC -c -o $t/c.o -xc -
extern _Thread_local int a;
int main() { return a; }
EOF

! $CC --ld-path=./ld64 -o $t/exe1 $t/b.so $t/c.o >& $t/log1
grep -Fq 'illegal thread local variable reference to regular symbol `_a`' $t/log1

! $CC --ld-path=./ld64 -o $t/exe2 $t/a.o $t/c.o >& $t/log2
grep -Fq 'illegal thread local variable reference to regular symbol `_a`' $t/log2
