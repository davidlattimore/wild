#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CXX -o $t/a.o -c -xc++ -
#include <iostream>
int foo() { std::cout << "foo "; return 3; }

int x = foo();
EOF

cat <<EOF | $CXX -o $t/b.o -c -xc++ -
#include <iostream>

int bar() { std::cout << "bar "; return 5; }
int y = bar();

int main() {
  std::cout << "main\n";
}
EOF

$CXX --ld-path=./ld64 -o $t/exe $t/a.o $t/b.o -Wl,-init_offsets
objdump -h $t/exe | grep -Eq '__init_offsets\s+00000008\s'
$t/exe | grep -q 'foo bar main'
