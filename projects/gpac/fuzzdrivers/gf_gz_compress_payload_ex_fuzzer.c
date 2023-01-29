#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/tools.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // fuzzing code goes here
    u8 * data = malloc(Size);
    if (!data) return 0;
    memcpy(data, Data, Size);
    u32 out_size = 0;
    u8 * out_comp_data = NULL;
    gf_gz_compress_payload_ex(&data, Size, &out_size, 0, 0, &out_comp_data);
    free(data);
    free(out_comp_data);
    return 0;
}
