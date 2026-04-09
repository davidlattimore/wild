#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -c -o $t/a.o -xc -
#include <stdio.h>

void hello() {
  printf("Hello world\n");
}
EOF

cat <<EOF | $CC -c -o $t/b.o -xc -
void foo() {}
EOF

rm -f $t/c.a
ar rcs $t/c.a $t/a.o $t/b.o

cat <<EOF | $CC -c -o $t/d.o -xc -
void hello();

int main() {
  hello();
}
EOF

$CXX --ld-path=./ld64 -o $t/exe $t/d.o $t/c.a
$t/exe | grep -q 'Hello world'

otool -tv $t/exe | grep -q '^_hello:'
! otool -tv $t/exe | grep -q '^_foo:' || false
