// This file duplicates some of the calls in middle1.

int shared1(void);

int call_shared1_from_far2(void) { return shared1(); }

int ifunc1(void);

int call_ifunc1_from_far2(void) { return ifunc1(); }

int ifunc2(void);

int call_ifunc2_from_far2(void) { return ifunc2(); }
