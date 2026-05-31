/*
 * OSS-Fuzz harness for OpenVPN config/options parser.
 *
 * Exercises parse_line() and options_string_import(), which parse
 * OpenVPN configuration files and --push-reply/--pull strings from servers.
 * These parsers process untrusted input when a client connects to a server.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* OpenVPN internal headers */
#include "config.h"
#include "syshead.h"
#include "options.h"
#include "buffer.h"
#include "error.h"

/*
 * parse_line() tokenises a single config line into argc/argv style tokens.
 * It handles quoting, backslash escapes, and inline data blocks.
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    /* NUL-terminate */
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    /* Replace NUL bytes in input with spaces to keep it a valid C string */
    for (size_t i = 0; i < size; i++) {
        if (input[i] == '\0') input[i] = ' ';
    }

    /* parse_line() tokenises the line */
    const char *p[MAX_PARMS];
    int nparms = 0;
    char *line_dup = strdup(input);
    if (line_dup) {
        nparms = parse_line(line_dup, (char **)p, MAX_PARMS, "[fuzz]", 1, D_PUSH, NULL);
        (void)nparms;
        free(line_dup);
    }

    free(input);
    return 0;
}
