#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct FileHeader {
  u8 magic[4];
  u8 class;
  u8 data;
  u8 ei_version;
  u8 os_abi;
  u8 abi_version;
  u8 padding[7];
  u16 ty;
  u16 machine;
  u32 e_version;
  u64 entry_point;
  u64 program_header_offset;
  u64 section_header_offset;
  u32 flags;
  u16 ehsize;
  u16 program_header_entry_size;
  u16 program_header_num;
  u16 section_header_entry_size;
  u16 section_header_num;
  u16 section_names_index;
};

struct ProgramHeader {
  u32 segment_type;
  u32 flags;
  u64 offset;
  u64 virtual_addr;
  u64 physical_addr;
  u64 file_size;
  u64 mem_size;
  u64 alignment;
};

extern const struct FileHeader __ehdr_start;

static void set_fs_register(void *address) {
  register int64_t rax __asm__("rax") = 158;     // arch_prctl
  register int64_t rdi __asm__("rdi") = 0x1002;  // ARCH_SET_FS
  register int64_t rsi __asm__("rsi") = (int64_t)address;
  __asm__ __volatile__("syscall"
                       : "+r"(rax)
                       : "r"(rdi), "r"(rsi)
                       : "rcx", "r11", "memory");
}

static u8 ***tcb;

u8 ***get_tcb(void) { return tcb; }

int init_tls(uint64_t base_address) {
  // A buffer to hold our TLS storage.
  static u8 tls_area[1024] __attribute__((aligned(8)));

  const u32 SHT_TLS = 7;

  u8 *t_out = tls_area;
  int num_headers = __ehdr_start.program_header_num;
  struct ProgramHeader *headers =
      (struct ProgramHeader *)((void *)(&__ehdr_start) +
                               __ehdr_start.program_header_offset);
  for (int i; i < num_headers; i++) {
    struct ProgramHeader *h = &headers[i];
    if (h->segment_type == SHT_TLS) {
      u8 *t_in = (u8 *)h->virtual_addr + base_address;
      for (int j = 0; j < h->mem_size; j++) {
        if (j < h->file_size) {
          *t_out = *t_in;
          t_in++;
        } else {
          // We're past file_size, initialise with zeros.
          *t_out = 0;
        }
        t_out++;
      }
      // Keep going until we're 8-byte aligned, otherwise the TCB might not have
      // the correct alignment.
      while ((((u64)t_out) & 0x7) != 0) {
        t_out++;
      }

      // Put a pointer to the TCB at the start of the TCB.
      u64 *tcb_u64 = (u64 *)t_out;
      tcb_u64[0] = (u64)tcb_u64;

      // Next entry in the TCB
      u64 *modules = &tcb_u64[2];
      modules[1] = (u64)tcb_u64;

      tcb_u64[1] = (u64)modules;

      // Point the GS register to the TCB.
      set_fs_register(t_out);
      tcb = (u8 ***)t_out;
      return 0;
    }
  }
  return 1;
}
