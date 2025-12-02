// This test verifies that we can perform a backtrace via different mechanisms.
// It avoids getting symbol names, because that can be unreliable on some
// platforms and instead just works out if the address is consistent with being
// part of the relevant function.

//#AbstractConfig:default
//#LinkerDriver:gcc
//#Object:backtrace-2.c
//#DiffEnabled:false
//#RequiresGlibc:true

//#Config:eh-frame:default
//#CompArgs:-O0 -fomit-frame-pointer

// TODO: Enable
// //#Config:sframe:default
// //#CompArgs:-O0 -fomit-frame-pointer -Wa,--gsframe
// //#RemoveSection:.eh_frame
// //#RemoveSection:.eh_frame_hdr

#define _GNU_SOURCE
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

int foo(void);
int bar(void);
int baz(void);
int main();
int check_backtrace(void);

struct Entry {
  int index;
  void* fn_ptr;
};

// List of functions that we expect in our backtrace.
static struct Entry ENTRIES[] = {
    {index : 0, fn_ptr : check_backtrace},
    {index : 1, fn_ptr : baz},
    {index : 2, fn_ptr : bar},
    {index : 3, fn_ptr : foo},
    {index : 4, fn_ptr : main},
};

size_t NUM_ENTRIES = sizeof(ENTRIES) / sizeof(ENTRIES[0]);

static int compare_entries(const void* a, const void* b) {
  const struct Entry* pa = a;
  const struct Entry* pb = b;
  if (pa->fn_ptr < pb->fn_ptr) return -1;
  if (pa->fn_ptr > pb->fn_ptr) return 1;
  return 0;
}

int check_backtrace(void) {
  void* buffer[32];
  int nptrs = backtrace(buffer, 32);
  if (nptrs <= 0) return 10;

  // Sort our expected entries by their address.
  qsort(ENTRIES, NUM_ENTRIES, sizeof(ENTRIES[0]), compare_entries);

  for (int f = 0; f < NUM_ENTRIES; f++) {
    void* addr = buffer[f];

    // Find the first entry that our backtrace address is after (or the end).
    size_t i = 0;
    while (i < NUM_ENTRIES && addr > ENTRIES[i].fn_ptr) {
      ++i;
    }

    if (i == 0) {
      return 20;
    }

    if (ENTRIES[i - 1].index != f) {
      return 50 + f * 10 + i;
    }
  }

  return 42;
}

int bar(void) { return baz(); }

int main() { return foo(); }
