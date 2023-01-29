#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/base_coding.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    u32 out_buffer_size = 2 * Size + 1;
    u8 *out_buffer = (u8 *)malloc(out_buffer_size);
    gf_base16_encode((u8 *)Data, Size, out_buffer, out_buffer_size);
    free(out_buffer);
    return 0;
}
