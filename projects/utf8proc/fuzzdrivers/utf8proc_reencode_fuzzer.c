#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "utf8proc.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    utf8proc_int32_t *buffer = malloc(Size * sizeof(utf8proc_int32_t));
    for (size_t i = 0; i < Size; i++) {
        buffer[i] = Data[i];
    }
    utf8proc_reencode(buffer, Size, UTF8PROC_COMPAT);
    free(buffer);
    return 0;
}
