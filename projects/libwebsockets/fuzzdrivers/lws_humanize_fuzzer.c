#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lws_config.h"
#include "libwebsockets.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return 0;
    }

    char buf[Size];
    int len = Size;
    int value = 0;
    const lws_humanize_unit_t schema[] = {
        {"B", 1, 1},
        {"KB", 1024, 1},
        {"MB", 1024 * 1024, 1},
        {"GB", 1024 * 1024 * 1024, 1},
        {"TB", 1024 * 1024 * 1024 * 1024, 1},
        {"PB", 1024 * 1024 * 1024 * 1024 * 1024, 1},
        {"EB", 1024 * 1024 * 1024 * 1024 * 1024 * 1024, 1},
        {"ZB", 1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024, 1},
        {"YB", 1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024, 1},
        {NULL, 0, 0}
    };

    lws_humanize(buf, len, value, schema);
    return 0;
}
