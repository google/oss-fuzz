#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "utf8proc.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    utf8proc_int32_t buffer[128];
    utf8proc_decompose(Data, Size, buffer, 128, 0);
    return 0;
}
