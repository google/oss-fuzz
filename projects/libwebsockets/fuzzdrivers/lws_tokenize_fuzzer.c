#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lws_config.h"
#include "libwebsockets.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    struct lws_tokenize ts;
    lws_tokenize_elem e;

    memset(&ts, 0, sizeof(ts));
    ts.len = Size;
    ts.start = Data;

    e = lws_tokenize(&ts);

    return 0;
}
