#!/bin/bash
. $(dirname $0)/common.inc

[ $CXX -xc -femit-dwarf-unwind=always /dev/null 2> /dev/null ] || skip

cat <<EOF | $CXX -arch x86_64 -c -o $t/a.o -xc++ - -femit-dwarf-unwind=always
int main() {
  try {
    throw 0;
  } catch (int x) {
    return x;
  }
  return 1;
}
EOF

$CXX -o $t/exe $t/a.o
$t/exe
