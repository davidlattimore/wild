# Wild doesn't yet properly support COMDAT groups. This test checks that we remove the group flag
# when doing partial linking so that we don't end up with a dangling grouped section. This isn't
# what our usual reference linkers do, since they have proper COMDAT support.
#
# TODO: Update this test when we add proper COMDAT support.

//#Arch: x86_64
//#LinkArgs:-r
//#RunEnabled:false
//#TestUpdateInPlace:true
//#ReferenceLinkers:
//#DiffEnabled:false
//#ExpectSection:.text.group_member flags=AX
//#NoSection:.group

.section .text.group_member,"axG",@progbits,group_signature,comdat
.globl group_signature
.type group_signature,@function
group_signature:
  ret
.size group_signature, .-group_signature
