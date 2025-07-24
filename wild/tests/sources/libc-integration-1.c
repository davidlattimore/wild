// This file deliberately has no outgoing relocations. This means that it
// shouldn't get any symbol versions, which then in turn checks that we can
// handle linking our executable against a mix of shared objects, some with
// symbol versions and some without.

int get_42(void) { return 42; }
