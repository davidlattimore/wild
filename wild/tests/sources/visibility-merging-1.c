// Even though the definition of `data1` from the main file is given priority over this definition,
// the fact that this definition is hidden causes the symbol to be hidden.
int data1  __attribute__ ((weak, visibility(("hidden")))) = 0x100;

// Similarly, this symbol makes the symbol of the same name from file protected.
int data3  __attribute__ ((weak, visibility(("protected")))) = 0x55;

int data4 __attribute__ ((weak, visibility(("hidden")))) = 0x99;
