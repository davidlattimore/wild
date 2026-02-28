// Test that R_AARCH64_PLT32 and R_AARCH64_GOTPCREL32 relocations are applied correctly.
//
// R_AARCH64_PLT32 (314): S + A - P, 32-bit PC-relative to PLT/function entry
// R_AARCH64_GOTPCREL32 (315): G(S) + A - P, 32-bit PC-relative to GOT entry
//
// These relocation types are missing from the upstream ELF header and object crate,
// so we use .reloc with numeric type IDs.

//#Object:aarch64-plt32-gotpcrel32-1.s
//#Object:runtime.c
//#LinkArgs:-z noexecstack
//#Arch: aarch64
//#SkipLinker:ld
//#DiffEnabled:false

.section .rodata, "a", @progbits
.p2align 2
plt32_ref:
    .reloc ., 314, target_func  // R_AARCH64_PLT32
    .word 0
gotpcrel32_ref:
    .reloc ., 315, target_func  // R_AARCH64_GOTPCREL32
    .word 0

.section .text, "ax", @progbits

.globl _start
.type _start, @function
_start:
    // === Test R_AARCH64_PLT32 ===
    // Load address of plt32_ref
    adrp x4, plt32_ref
    add x4, x4, :lo12:plt32_ref
    // Load the 32-bit signed PC-relative value written by the linker
    ldrsw x5, [x4]
    // Compute target address: plt32_ref + value = target_func (or its PLT stub)
    add x6, x4, x5
    // Call it; target_func should return 100 in x0
    blr x6
    cmp x0, #100
    b.ne .Lfail_plt32

    // === Test R_AARCH64_GOTPCREL32 ===
    // Load address of gotpcrel32_ref
    adrp x4, gotpcrel32_ref
    add x4, x4, :lo12:gotpcrel32_ref
    // Load the 32-bit signed PC-relative value written by the linker
    ldrsw x5, [x4]
    // Compute GOT entry address: gotpcrel32_ref + value = &GOT[target_func]
    add x6, x4, x5
    // Load function address from GOT entry
    ldr x7, [x6]
    // Call it; target_func should return 100 in x0
    blr x7
    cmp x0, #100
    b.ne .Lfail_gotpcrel32

    // Both relocations work correctly; exit with code 42 (success)
    mov x0, #42
    b exit_syscall

.Lfail_plt32:
    mov x0, #101
    b exit_syscall

.Lfail_gotpcrel32:
    mov x0, #102
    b exit_syscall
.size _start, .-_start
