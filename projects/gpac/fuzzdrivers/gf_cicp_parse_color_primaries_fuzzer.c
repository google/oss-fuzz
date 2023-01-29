#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/constants.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *val = (char *) malloc(Size + 1);
    memcpy(val, Data, Size);
    val[Size] = 0;
    gf_cicp_parse_color_primaries(val);
    free(val);
    return 0;
}
