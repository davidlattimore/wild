//#Config:default
//#LinkArgs:--entry=missing --no-gc-sections
//#ExpectWarning:cannot find entry symbol .*missing
//#ExpectEntry:first_function
//#RunEnabled:false

void first_function(void) {}
