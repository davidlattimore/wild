__attribute__((weak, visibility("protected"))) extern int get_value(void);

int other_func(void) {
    if (get_value) {
        return get_value();
    }
    return -1;
}
