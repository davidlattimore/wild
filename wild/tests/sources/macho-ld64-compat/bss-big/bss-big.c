// A large zero-initialised array lives in `__bss` (S_ZEROFILL). Exercises
// the writable-DATA segment when the only content is bss — wild has to
// keep the segment sized correctly even though nothing is written to the
// file for the bss range. 4 KB pushes past the 1-page threshold to catch
// any miscomputed vmsize/filesize relationship.
int big[1024];
int main(void) {
  big[0] = 42;
  return big[0] - 42;
}
