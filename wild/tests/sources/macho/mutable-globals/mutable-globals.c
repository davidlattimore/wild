// Tests that mutable global data (__data section) works correctly.
//#Object:mutable-globals1.c

extern int counter;
void increment(void);

int main() {
  increment();
  increment();
  increment();
  return counter == 3 ? 42 : 1;
}
