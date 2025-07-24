#if (VARIANT & 16) == 0
#if (VARIANT & 8) != 0
int weak_var1 __attribute__((weak)) = 64;
int weak_arr1[] __attribute__((weak)) = {4, 4, 4, 4};
int weak_var3 __attribute__((weak)) = 2;
#else
int weak_var1 = 64;
int weak_arr1[4] = {4, 4, 4, 4};
int weak_var3 = 8;
#endif
#endif

int strong_var1 = 128;
int strong_var2 = 0;
