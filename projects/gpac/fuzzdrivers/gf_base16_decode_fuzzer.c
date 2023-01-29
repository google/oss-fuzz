#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/base_coding.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    u8 *out_buffer = malloc(Size);
    gf_base16_decode((u8*)Data, Size, out_buffer, Size);
    free(out_buffer);
    return 0;  // Non-zero return values are reserved for future use.
}
