static int dead_start_stop_value __attribute__((used, section("dead_start_stop"))) = 99;

extern int __start_dead_start_stop[];
extern int __stop_dead_start_stop[];

__attribute__((used, noinline, section(".text.dead_start_stop_ref"))) static int
dead_start_stop_ref(void) {
  return *__start_dead_start_stop + (__stop_dead_start_stop - __start_dead_start_stop);
}
