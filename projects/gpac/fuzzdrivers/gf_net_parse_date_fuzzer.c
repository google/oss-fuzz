#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/tools.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    char *str = (char *)malloc(Size + 1);
    if (!str)
        return 0;
    memcpy(str, Data, Size);
    str[Size] = 0;
    gf_net_parse_date(str);
    free(str);
    return 0;
}
