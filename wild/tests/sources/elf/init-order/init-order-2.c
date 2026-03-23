// Constructors

__attribute__((constructor(2000))) void init_2000c() {}
__attribute__((constructor(2000))) void init_2000d() {}
__attribute__((constructor(1000))) void init_1000c() {}
__attribute__((constructor(1000))) void init_1000d() {}
__attribute__((constructor)) void init_c() {}
__attribute__((constructor)) void init_d() {}

// Destructors

__attribute__((destructor(2000))) void fini_2000c() {}
__attribute__((destructor(2000))) void fini_2000d() {}
__attribute__((destructor(1000))) void fini_1000c() {}
__attribute__((destructor(1000))) void fini_1000d() {}
__attribute__((destructor)) void fini_c() {}
__attribute__((destructor)) void fini_d() {}
