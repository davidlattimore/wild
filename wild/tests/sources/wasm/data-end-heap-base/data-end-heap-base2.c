extern char __data_end;
extern char __heap_base;

int y = 2;

unsigned long data_end_from_other_tu(void) { return (unsigned long)&__data_end; }
unsigned long heap_base_from_other_tu(void) { return (unsigned long)&__heap_base; }
