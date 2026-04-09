#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
int main() {}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o \
  -Wl,-add_ast_path,foo -Wl,-add_ast_path,bar

dsymutil -s $t/exe | grep -q 'N_AST.*foo'
dsymutil -s $t/exe | grep -q 'N_AST.*bar'
