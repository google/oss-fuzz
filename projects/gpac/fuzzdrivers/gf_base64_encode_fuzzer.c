#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/base_coding.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    u8 *out_buffer = (u8 *)malloc(Size * 2);
    if (out_buffer == NULL) {
        return 0;
    }
    gf_base64_encode(Data, Size, out_buffer, Size * 2);
    free(out_buffer);
    return 0;
}
