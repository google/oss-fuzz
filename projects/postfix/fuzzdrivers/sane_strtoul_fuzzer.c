#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "sane_strtol.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1)
        return 0;
    if (Data[0] == 0)
        return 0;
    char *end;
    sane_strtoul((const char *)Data, &end, 10);
    return 0;
}
