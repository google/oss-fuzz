#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lws_config.h"
#include "libwebsockets.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *out = (char*)malloc(Size);
    if (!out) return 0;
    lws_b64_decode_string_len((const char*)Data, Size, out, Size);
    free(out);
    return 0;
}
