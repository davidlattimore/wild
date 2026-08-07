//#Object:runtime.c
// TODO: We need support for section renaming to match ld and lld behavior.
// In both, (__DATA, __const) is renamed to (__DATA_CONST, __const).
// https://github.com/apple-oss-distributions/ld64/blob/f60a74eaa2c99585de1dc0f2820e7a9f8aaf522c/src/ld/Options.cpp#L5223-L5263.
//#ReferenceLinkers:
//#ExpectSym:_data_value section="__const",segment="__DATA"
//#ExpectSym:_data_const_value section="__const",segment="__DATA_CONST"
//#NoSection:__got

#include "../common/runtime.h"

__attribute__((used, section("__DATA,__const"))) const long data_value = 1;

__attribute__((used, section("__DATA_CONST,__const"))) const long data_const_value = 2;

void main(void) { exit_syscall(42); }
