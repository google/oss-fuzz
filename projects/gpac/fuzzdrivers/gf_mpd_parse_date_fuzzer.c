#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/mpd.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *data = (char *)malloc(Size + 1);
    memcpy(data, Data, Size);
    data[Size] = 0;
    gf_mpd_parse_date(data);
    free(data);
    return 0;
}
