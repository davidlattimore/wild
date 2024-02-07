#include <stdint.h>

#include "exit.h"

typedef uint32_t u32;

struct EhFrameEntry {
    u32 length;
    u32 cie_ptr;
};

static char EH_FRAME_START[] __attribute__((section(".eh_frame"), aligned(__alignof__ (void *)))) = {};

extern char EH_FRAME_END[];

void _start(void) {
    const struct EhFrameEntry* frame1 = (struct EhFrameEntry*) EH_FRAME_START;

    // The first entry should be a CIE. Its length should be non-zero.
    if (frame1->length == 0) {
        exit_syscall(101);
    }
    // Since it's a CIE, it's cie_ptr should be zero.
    if (frame1->cie_ptr != 0) {
        exit_syscall(102);
    }

    const struct EhFrameEntry* frame2 = (struct EhFrameEntry*) (EH_FRAME_START + frame1->length + 4);
    // The second entry should be an FDE. Its length should be non-zero.
    if (frame2->length == 0) {
        exit_syscall(103);
    }
    // Its CIE pointer should point back to the start of first entry. This pointer is relative to
    // the position of the pointer, so we need to add the offset of the pointer within the entry
    // (4). The length field doesn't include the size of the length (4 bytes), so we need to add
    // that too.
    if (frame2->cie_ptr != frame1->length + 8) {
        exit_syscall(104);
    }

    int eh_frame_len = EH_FRAME_END - EH_FRAME_START;

    if (eh_frame_len == 0) {
        exit_syscall(105);
    }

    // Make sure that all memory between start and end is valid to read.
    int total = 0;
    for (const char* c = EH_FRAME_START; c < EH_FRAME_END; c++) {
        total += *c;
    }
    if (total == 0) {
        exit_syscall(106);
    }

    exit_syscall(42);
}
