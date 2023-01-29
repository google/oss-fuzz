#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lws_config.h"
#include "libwebsockets.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *escaped = malloc(Size * 3 + 1);
    if (escaped == NULL) return 0;
    lws_urlencode(escaped, (const char *)Data, Size);
    free(escaped);
    return 0;
}
