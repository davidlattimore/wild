#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc - -fPIC
#include <stdio.h>

int a = 5;
int *b = &a;

void print() {
  printf("%d %d\n", a, *b);
}
EOF

$CC --ld-path=./ld64 -shared -o $t/b.dylib $t/a.o

cat <<EOF | $CC -o $t/c.o -c -xc - -fPIC
void print();
int main() { print(); }
EOF

$CC --ld-path=./ld64 -o $t/exe $t/b.dylib $t/c.o
$t/exe | grep -q '^5 5$'
