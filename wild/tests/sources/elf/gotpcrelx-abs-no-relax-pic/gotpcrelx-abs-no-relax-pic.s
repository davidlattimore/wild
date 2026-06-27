// Test that GOTPCRELX access to a hidden absolute symbol in a shared object
// produces correct runtime behavior. Wild relaxes to a direct immediate
// (matching GNU ld), while lld keeps the GOT access. Both are correct.
// lld is used as reference linker since GNU ld uses different relaxation.
//#Arch:x86_64
//#LinkArgs:--no-gc-sections -shared
//#ReferenceLinkers:lld
//#RunDynSym:get_bar
//#DiffIgnore:.dynamic.DT_FLAGS_1.NOW
//#DiffIgnore:section.got
//#DiffIgnore:rel.extra-opt.R_X86_64_REX_GOTPCRELX.RexMovIndirectToAbsolute*
.text
.globl get_bar
.type get_bar, @function
get_bar:
    movq bar@GOTPCREL(%rip), %rax
    ret
.data
.global bar
.hidden bar
bar = 42
