#!/bin/bash
. $(dirname $0)/common.inc

cat <<EOF | $CC -o $t/a.o -c -xobjective-c -
#import <Foundation/NSObject.h>
@interface MyClass : NSObject
@end
@implementation MyClass
@end
EOF

ar rcs $t/b.a $t/a.o

cat <<EOF | $CC -o $t/c.o -c -xc -
int main() {}
EOF

$CC -o $t/exe $t/c.o $t/b.a
! nm $t/exe | grep -q _OBJC_CLASS_ || false

! $CC -o $t/exe $t/c.o $t/b.a -Wl,-ObjC > $t/log 2>&1
grep -q _OBJC_CLASS_ $t/log
