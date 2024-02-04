// A very simplistic implementation of TLS initialisation for use when we aren't linking against
// libc. Definitely won't work with multiple threads, but should be enough for access TLS variables
// from the main thread. Returns 0 on success, 1 if no TLS segment was found.
int init_tls(void);
