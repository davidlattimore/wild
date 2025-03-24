#include "gnu-unique.h"

typedef int(*get_int_fn_t)(int);

extern "C" {

get_int_fn_t get_fn1(void) {
    return get_value<int>;
}

}
