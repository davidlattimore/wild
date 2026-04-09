#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
#include <stdio.h>

char msg1[] = "Hello world";
char msg2[] = "Howdy world";

void hello() {
  printf("%s\n", msg1);
}

void howdy() {
  printf("%s\n", msg2);
}

int main() {
  hello();
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o -Wl,-dead_strip
$t/exe | grep -q 'Hello world'
otool -tVj $t/exe > $t/log
grep -q 'hello:' $t/log
! grep -q 'howdy:' $t/log || false
