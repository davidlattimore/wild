/*
 * Trampoline for the linker plugin message callback.
 *
 * The Gold plugin API defines the message callback as:
 *   ld_plugin_status (*ld_plugin_message)(int level, const char *format, ...)
 *
 * Rust cannot implement C variadic functions on stable, so we implement the
 * callback here in C. It formats the printf-style message and forwards the
 * result to wild_handle_plugin_message (defined in linker_plugins.rs).
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

/* Rust function we call with the fully-formatted message string. */
extern void wild_handle_plugin_message(int level, const char *message);

void wild_plugin_message_callback(int level, const char *fmt, ...) {
    va_list args1, args2;
    va_start(args1, fmt);
    va_copy(args2, args1);

    int len = vsnprintf(NULL, 0, fmt, args1);
    va_end(args1);

    if (len < 0) {
        va_end(args2);
        /* Fall back to the raw format string if sizing failed. */
        wild_handle_plugin_message(level, fmt);
        return;
    }

    char *buf = malloc((size_t)len + 1);
    if (buf == NULL) {
        va_end(args2);
        wild_handle_plugin_message(level, fmt);
        return;
    }

    vsnprintf(buf, (size_t)len + 1, fmt, args2);
    va_end(args2);

    wild_handle_plugin_message(level, buf);
    free(buf);
}
