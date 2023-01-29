#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/base_coding.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    u8 *out_buffer = malloc(3 * Size);
    if (out_buffer == NULL) {
        return 0;
    }
    gf_base64_decode(Data, Size, out_buffer, 3 * Size);
    free(out_buffer);
    return 0;
}
