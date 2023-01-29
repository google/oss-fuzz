#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lws_config.h"
#include "libwebsockets.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char buf[128];
    int t[6];
    int len = Size;
    int ret = 0;
    if (Size < 4)
        return ret;
    memcpy(t, Data, 4);
    ret = lws_http_date_render_from_unix(buf, len, t);
    return ret;
}
