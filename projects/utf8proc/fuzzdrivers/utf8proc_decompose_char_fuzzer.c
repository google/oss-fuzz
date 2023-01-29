#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "utf8proc.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4)
        return 0;
    utf8proc_int32_t codepoint = (Data[0] << 24) | (Data[1] << 16) | (Data[2] << 8) | Data[3];
    utf8proc_int32_t dst[10];
    utf8proc_decompose_char(codepoint, dst, 10, 0, 0);
    return 0;
}
