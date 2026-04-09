#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xobjective-c -
#import <Foundation/Foundation.h>
int main() {
  NSProcessInfo *info = [NSProcessInfo processInfo];
  NSLog(@"processName: %@", [info processName]);
}
EOF

$CC --ld-path=./ld64 -o $t/exe $t/a.o -framework foundation -Wl,-ObjC
$t/exe 2>&1 | grep -Fq 'processName: exe'
