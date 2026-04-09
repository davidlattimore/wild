#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int foo();

int main() {
  foo();
}
EOF

! $CC --ld-path=./ld64 -o $t/exe $t/a.o 2> $t/log || false
grep -q 'undefined symbol: .*\.o: _foo' $t/log
