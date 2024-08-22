void *memset(void *s, int c, unsigned long n)
{
    char *ptr = s;
    for (unsigned long i = 0; i < n; ++i)
        *(ptr + i) = c;

    return s;
}

void* memcpy(void* dest, const void* src, unsigned long num)
{
	char* d = dest;
	const char* s = src;
	for (int i = 0; i < num; i++) {
		d[i] = s[i];
	}
	return dest;
}
