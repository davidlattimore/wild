// Tests that __const section data is correctly placed and accessible.
//#ExpectSym:table

static const int table[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
int main() {
  int sum = 0;
  for (int i = 0; i < 10; i++) sum += table[i];
  return sum == 55 ? 42 : 1;
}
