#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xc -
void foo() {}
__attribute__((visibility("hidden"))) void bar() {}
EOF

$CC --ld-path=./ld64 -shared -o $t/b.dylib $t/a.o
objdump --macho --exports-trie $t/b.dylib > $t/log
grep -q _foo $t/log
! grep -q _bar $t/log || false
