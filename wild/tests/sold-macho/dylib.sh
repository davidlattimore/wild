#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -c -o $t/a.o -xc -
#include <stdio.h>
char world[] = "world";

char *hello() {
  return "Hello";
}
EOF

$CC --ld-path=./ld64 -o $t/b.dylib -shared $t/a.o

cat <<EOF | $CC -o $t/c.o -c -xc -
#include <stdio.h>

char *hello();
extern char world[];

int main() {
  printf("%s %s\n", hello(), world);
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/c.o $t/b.dylib
$t/exe | grep -q 'Hello world'
