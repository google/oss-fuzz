#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/tools.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;
    u8 *out;
    u32 out_size;
    gf_gz_decompress_payload((u8 *)Data, Size, &out, &out_size);
    return 0;
}
