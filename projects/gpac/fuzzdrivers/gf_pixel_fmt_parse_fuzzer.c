#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/constants.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    char *str = (char *)malloc(Size + 1);
    memcpy(str, Data, Size);
    str[Size] = '\0';
    gf_pixel_fmt_parse(str);
    free(str);
    return 0;
}
