// We don't currently support strings in merge sections if they're missing their
// null terminator. GNU ld does support this. This test ensures that we give the
// expected error.

//#SkipLinker:ld
//#ExpectError:String in merge-string section is not null-terminated
//#Object:string-merge-missing-null-1.s
