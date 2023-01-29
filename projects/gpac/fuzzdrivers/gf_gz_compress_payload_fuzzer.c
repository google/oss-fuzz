#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "gpac/tools.h"


extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    u8 * data = NULL;
    u32 data_len = 0;
    u32 out_size = 0;

    data = (u8 *) malloc(Size);
    memcpy(data, Data, Size);
    data_len = Size;

    gf_gz_compress_payload(&data, data_len, &out_size);
    free(data);
    return 0;
}
