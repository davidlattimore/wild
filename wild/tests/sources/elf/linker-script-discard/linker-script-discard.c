//#Mode:dynamic
//#RunEnabled:false
//#SkipLinker:ld
//#EnableLinker:lld
//#LinkArgs:-shared -z now -T ./linker-script-discard.ld
//#DiffIgnore:section.got
//#DiffIgnore:segment.LOAD.RX.alignment
//#DiffIgnore:segment.LOAD.RWX.alignment
// Wild does not emit the `.eh_frame` section as all code sections are discarded, but lld still
// emits the CIE.
//#DiffIgnore:section.eh_frame
//#DoesNotContain:/DISCARD/
//#DoesNotContain:.text
//#NoSym:foo

int foo() { return 0; }
