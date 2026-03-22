//#AbstractConfig:default
//#Object:runtime.c
//#Object:ptr_black_box.c

//#Config:no-pie:default
//#LinkArgs:-no-pie -znow

//#Config:pie:default

#include "ptr_black_box.h"
#include "runtime.h"

extern char _etext;
extern char __etext;
extern char _edata;
extern char _end;

int data_var = 123;

void _start(void) {
  runtime_init();

  if (ptr_to_int(&_etext) == 0) {
    exit_syscall(10);
  }

  if (ptr_to_int(&_etext) <= ptr_to_int(&_start)) {
    exit_syscall(11);
  }

  if (ptr_to_int(&__etext) != ptr_to_int(&_etext)) {
    exit_syscall(12);
  }

  if (ptr_to_int(&_edata) == 0) {
    exit_syscall(13);
  }

  if (ptr_to_int(&_edata) <= ptr_to_int(&data_var)) {
    exit_syscall(14);
  }

  if (ptr_to_int(&_edata) <= ptr_to_int(&_etext)) {
    exit_syscall(15);
  }

  if (ptr_to_int(&_end) == 0) {
    exit_syscall(16);
  }

  // _end (end of .bss) should be >= _edata (end of .data). They can be equal
  // when there is no .bss content, as is the case in this test.
  if (ptr_to_int(&_end) < ptr_to_int(&_edata)) {
    exit_syscall(17);
  }

  exit_syscall(42);
}
