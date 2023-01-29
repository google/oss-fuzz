#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/constants.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *buf = (char *)malloc(Size + 1);
    if (!buf) return 0;
    memcpy(buf, Data, Size);
    buf[Size] = 0;
    gf_codecid_parse(buf);
    free(buf);
    return 0;
}
