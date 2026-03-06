// Minimal PE entry point — no CRT, just return an exit code which apparently works without c runtime on windows
int entry(void) {
    return 42;
}
