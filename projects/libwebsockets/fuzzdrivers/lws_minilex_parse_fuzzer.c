#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "lws_config.h"
#include "libwebsockets.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int lex[1024] = {0};
    int ps = 0;
    int match = 0;
    if (Size > 1024) {
        return 0;
    }
    for (size_t i = 0; i < Size; i++) {
        lws_minilex_parse(lex, &ps, Data[i], &match);
    }
    return 0;
}
