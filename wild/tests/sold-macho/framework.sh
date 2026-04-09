#!/bin/bash
. $(dirname $0)/common.inc

mkdir -p $t/Foo.framework

cat <<EOF | $CC -o $t/Foo.framework/Foo -shared -xc -
#include <stdio.h>
void hello() {
  printf("Hello world\n");
}
EOF

cat <<EOF | $CC -o $t/a.o -c -xc -
void hello();
int main() {
  hello();
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-F$t -Wl,-framework,Foo
$t/exe | grep -q 'Hello world'
