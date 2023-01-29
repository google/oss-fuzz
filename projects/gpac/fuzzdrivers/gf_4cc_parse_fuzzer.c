#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/tools.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;
    char buf[5];
    memcpy(buf, Data, 4);
    buf[4] = 0;
    gf_4cc_parse(buf);
    return 0;
}
