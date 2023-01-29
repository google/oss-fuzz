#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "utf8proc.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;
    utf8proc_uint8_t *dstptr = NULL;
    utf8proc_map(Data, Size, &dstptr, 0);
    free(dstptr);
    return 0;
}
