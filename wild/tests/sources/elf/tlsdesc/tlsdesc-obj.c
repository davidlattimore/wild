_Thread_local long g1 = 1;
static _Thread_local long l2 = 2;
static _Thread_local long l3 = 3;
static _Thread_local long l4 = 4;
_Thread_local long g5 = 5;
_Thread_local long g6 = 6;
_Thread_local long g7 = 7;
static _Thread_local long bss1 = 0;
_Thread_local long bss2 = 0;

int get_value() {
  bss1 = 6;
  bss2 = 8;

  return g1 + l2 + l3 + l4 + g5 + g6 + g7 + bss1 + bss2;
}
