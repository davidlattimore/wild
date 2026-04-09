#!/bin/bash
. $(dirname $0)/common.inc

echo ' -help' > $t/rsp
./ld64 @$t/rsp | grep -q Usage
